# Route VPN clients via Cloudflare WARP (kernel WireGuard)

This addon routes **IKEv2 / L2TP / XAuth** client internet traffic through **Cloudflare WARP** on the server, while **SSH and the host itself stay on the direct gateway** (no lockout). It uses kernel WireGuard for best performance.

## How it works

* WireGuard interface `warp` with `Table = off` — `wg-quick` never touches the main default route, so SSH stays reachable.
* Endpoint `engage.cloudflareclient.com:2408` gets a `/32` bypass via `$NET_IFACE` gateway — avoids routing loop.
* Policy routing table `51820`:
  * `ip rule from 192.168.42.0/24 lookup 51820` (L2TP)
  * `ip rule from 192.168.43.0/24 lookup 51820` (XAuth + IKEv2)
  * `ip -6 rule from fddd:500:500:500::/64 lookup 51820` (if IPv6 enabled)
  * `ip route add default dev warp table 51820`
* NAT: `iptables -t nat -A POSTROUTING -s <vpn_subnet> -o warp -j MASQUERADE` (plus `ip6tables` for IPv6)
* Performance: MTU 1280, MSS clamp (`--clamp-mss-to-pmtu`), BBR/fq preserved, `rp_filter=0` on `warp`, `PersistentKeepalive=25`, kernel WG (no userspace `warp-go`).

Original VPN MASQUERADE via `$NET_IFACE` is kept as fallback — if WARP is down, clients transparently fall back to direct.

## Requirements

* VPN already installed via `vpnsetup_*.sh` (any OS: Ubuntu/Debian, CentOS/RHEL/Rocky/Alma/Oracle, Alpine, Amazon Linux 2)
* Root, WireGuard kernel support (`wireguard-tools` will be installed if missing)
* A WARP WireGuard profile. The script will find or create one in this order:
  1. `$WARP_CONF_SRC` env if set
  2. Existing `/etc/wireguard/warp.conf`
  3. Any `wgcf-profile.conf` in `./`, `/opt/`, `/etc/wireguard/`, `/root/`
  4. `wgcf-account.toml` -> `wgcf generate`
  5. `wgcf register --accept-tos && wgcf generate` (auto)

`wgcf` is auto-downloaded from `ViRb3/wgcf` if needed.

## Quick start (existing server)

```bash
# 1) get the addon (from your fork or upstream)
wget https://raw.githubusercontent.com/arnnis/setup-ipsec-vpn/master/extras/warp.sh -O warp.sh
# or if you pushed this branch:
# wget https://raw.githubusercontent.com/arnnis/setup-ipsec-vpn/master/extras/warp.sh -O warp.sh

# 2) if you already have a wgcf profile on your PC, upload it:
# scp wgcf-profile.conf root@SERVER:/opt/wgcf-profile.conf
# or WARP_CONF_SRC=/path/to/wgcf-profile.conf sudo bash warp.sh

# 3) enable (idempotent, safe to re-run, SSH stays up)
sudo bash warp.sh

# check
sudo bash warp.sh status
# should show: wg show warp has handshake, ip rule from 192.168.43.0/24 -> 51820, main default via eth0

# test: connect IKEv2 client, then on client:
curl https://ifconfig.co   # should show Cloudflare IP, not server IP
# on server, SSH still via direct:
ip route get 1.1.1.1  # main via eth0
ip route get 162.159.193.1  # WARP endpoint via eth0 bypass
```

## Customization

```bash
sudo WARP_TABLE=100 WARP_IF=warp WARP_CONF_SRC=/etc/wireguard/mywarp.conf bash warp.sh
sudo WARP_ENDPOINT=162.159.192.1:2408 bash warp.sh
```

## Management

```bash
sudo bash warp.sh status     # show wg, rules, routes, iptables, endpoint bypass
sudo bash warp.sh restart    # re-apply routing/nat (handy after reboot/debug)
sudo bash warp.sh uninstall  # remove WARP routing & disable wg-quick@warp (VPN reverts to direct)
# to re-enable: sudo bash warp.sh
```

Re-running `sudo bash warp.sh` is safe — it patches `/etc/wireguard/warp.conf` to `Table=off`, recreates helpers, re-adds rules.

## Boot persistence

* `systemd`: `wg-quick@warp.service` enabled with drop-in `After=network-online.target`, helpers as `PostUp`/`PreDown`.
* `OpenRC` (Alpine): `rc-update add wg-quick.warp`.
* Helpers `/usr/local/sbin/warp-up.sh` / `warp-down.sh` are called by `warp.conf` and also on `restart`.

## Troubleshooting

```bash
systemctl status wg-quick@warp
journalctl -u wg-quick@warp -n 50
wg show warp
cat /etc/wireguard/warp.conf  # must contain Table = off and PostUp = /usr/local/sbin/warp-up.sh
ip rule show; ip route show table 51820; iptables -t nat -S | grep warp
bash -x /usr/local/sbin/warp-up.sh  # verbose re-apply (SSH safe)
```

*No handshake* → endpoint blocked or time skewed (`timedatectl`), try `wg-quick down warp; wg-quick up warp`.
*Client still shows server IP* → policy rules not hit: `ip rule show` must have `from 192.168.43.0/24 lookup 51820`. Re-run `warp.sh`.
*SSH risk* → script never replaces main default; verify `ip route show default` is via `$NET_IFACE`, not `warp`.

## Uninstall

```bash
sudo bash extras/warp.sh uninstall
# or: sudo wg-quick down warp; sudo systemctl disable wg-quick@warp
# config left at /etc/wireguard/warp.conf - delete manually if desired
```

## Performance notes

* Kernel WireGuard > userspace `warp-go`/`cloudflare-warp` (lower CPU, GRO, no extra TUN).
* MTU 1280 matches WARP; MSS clamp avoids fragmentation — keep `net.ipv4.tcp_congestion_control=bbr` and `fq` from base VPN sysctl.
* `PersistentKeepalive=25` keeps NAT mapping for Cloudflare.

