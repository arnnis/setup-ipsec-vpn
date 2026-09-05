# Route VPN clients via ProtonVPN (free WireGuard)

This addon routes **IKEv2 / L2TP / XAuth** client internet traffic through a **ProtonVPN (Free plan) WireGuard** server on your VPS, while **SSH and the host itself stay on the direct gateway** (no lockout). It is the same design as the [WARP addon](warp.md) and uses kernel WireGuard.

## How it works

* WireGuard interface `proton` with `Table = off` — `wg-quick` never touches the main default route, so SSH stays reachable.
* Your ProtonVPN server's endpoint gets a `/32` bypass via `$NET_IFACE` gateway — avoids a routing loop.
* Policy routing table `51821`:
  * `ip rule from 192.168.42.0/24 lookup 51821` (L2TP)
  * `ip rule from 192.168.43.0/24 lookup 51821` (XAuth + IKEv2)
  * `ip -6 rule from fddd:500:500:500::/64 lookup 51821` (only when the Proton profile has an IPv6 address and the base VPN has IPv6 enabled)
  * `ip route add default dev proton table 51821`
* NAT: `iptables -t nat -I POSTROUTING 1 -s <vpn_subnet> -o proton -j MASQUERADE`
* Performance: kernel WireGuard, MTU 1420 (ProtonVPN standard; a profile-defined MTU is kept), MSS clamp (`--clamp-mss-to-pmtu`), BBR/fq preserved, `rp_filter=0` on `proton`, `PersistentKeepalive = 25`.

Original VPN MASQUERADE via `$NET_IFACE` is kept as fallback — if ProtonVPN is down, clients transparently fall back to direct.

> **IPv6:** if your downloaded profile is IPv4-only, IPv6 client traffic is *not* routed through Proton (it keeps using the base VPN's direct IPv6 NAT), so IPv6 never blackholes. If the profile includes an IPv6 address, IPv6 is routed via Proton too.

## Requirements

* VPN already installed via `vpnsetup_*.sh` (any OS: Ubuntu/Debian, CentOS/RHEL/Rocky/Alma/Oracle, Alpine, Amazon Linux 2)
* Root, WireGuard kernel support (`wireguard-tools` will be installed if missing)
* A **ProtonVPN WireGuard profile for your account** (see next section)

## One-time: get your ProtonVPN WireGuard profile

Unlike Cloudflare WARP (which allows anonymous registration via `wgcf`), ProtonVPN WireGuard configs are **bound to your Proton account** — the generated `PrivateKey` is tied to your login and cannot be auto-created. The FREE plan supports WireGuard, so:

1. Sign in at <https://account.protonvpn.com/downloads> (Proton also calls this the "WireGuard configuration" section).
2. Pick any **Free** server location and download the WireGuard `.conf` (it contains `[Interface]` + `PrivateKey` + `[Peer]` sections).
3. Upload it to your server, e.g.:
   ```bash
   scp ~/Downloads/nl-free-01.protonvpn.net.conf root@YOUR_SERVER:/root/protonvpn-free.conf
   ```
4. Keep the file private (`chmod 600`) — it contains your account's WireGuard private key.

Notes:

* Free accounts can connect **one device at a time** — while this gateway is connected, don't also connect the same Proton account from your phone/PC.
* Want a different country later? Download another free-server `.conf` and re-run the install with the new `PROTON_CONF_SRC`.

## Quick start (existing server)

```bash
# 1) get the addon
wget https://raw.githubusercontent.com/arnnis/setup-ipsec-vpn/master/extras/proton.sh -O proton.sh

# 2) install / enable (idempotent, safe to re-run, SSH stays up)
sudo PROTON_CONF_SRC=/root/protonvpn-free.conf bash proton.sh

# or, if you saved the conf as /etc/wireguard/proton.conf, a bare run works too:
# sudo bash proton.sh

# check
sudo bash proton.sh status
# should show: wg show proton has handshake, ip rule from 192.168.43.0/24 -> 51821, main default via eth0

# test: connect IKEv2 client, then on client:
curl https://ifconfig.co   # should show a ProtonVPN IP, not server IP
# on server, SSH still via direct:
ip route get 1.1.1.1                 # main via eth0
ip route get <proton-endpoint-ip>    # endpoint via eth0 bypass
```

The install command auto-detects the profile in this order:

1. `PROTON_CONF_SRC` env (recommended)
2. Existing `/etc/wireguard/proton.conf`
3. Well-known upload paths: `/opt/protonvpn-free.conf`, `/root/protonvpn-free.conf`, `/root/proton-free.conf`, `$PWD/protonvpn-free.conf`, ...
4. Any `.conf` in `$PWD`, `/root`, `/opt`, `/etc/wireguard` that looks like a ProtonVPN profile (filename contains `proton`, or endpoint mentions `protonvpn`, or tunnel address is Proton's `10.2.0.2` / `10.3.0.2` / `10.4.0.2` NAT range)

If nothing is found, the script prints the download instructions above and exits.

## Customization

```bash
sudo PROTON_TABLE=100 PROTON_IF=proton PROTON_CONF_SRC=/etc/wireguard/myproton.conf bash proton.sh
```

## Management

```bash
sudo bash proton.sh status     # show wg, rules, routes, iptables, endpoint bypass, SSH-safety check
sudo bash proton.sh restart    # re-apply routing/nat (handy after reboot/debug)
sudo bash proton.sh uninstall  # remove ProtonVPN routing & disable wg-quick@proton (VPN reverts to direct)
# to re-enable: sudo bash proton.sh
```

Re-running `sudo bash proton.sh` is safe — it rebuilds `/etc/wireguard/proton.conf` (`Table = off`, `PostUp` helper, MTU, keepalive), recreates the helpers and re-adds the rules.

## Switching between WARP and ProtonVPN

Both addons route the **same** VPN client subnets, so only one can be active at a time:

```bash
# WARP -> Proton
sudo bash warp.sh uninstall
sudo PROTON_CONF_SRC=/root/protonvpn-free.conf bash proton.sh

# Proton -> WARP
sudo bash proton.sh uninstall
sudo bash warp.sh
```

Their configs and systemd units (`wg-quick@warp` / `wg-quick@proton`) can coexist — they simply must not be enabled together.

## Boot persistence

* `systemd`: `wg-quick@proton.service` enabled with drop-in `After=network-online.target`, helpers as `PostUp`/`PreDown`.
* `OpenRC` (Alpine): `rc-update add wg-quick.proton`.
* Helpers `/usr/local/sbin/proton-up.sh` / `proton-down.sh` are called by `proton.conf` and also on `restart`.

## Troubleshooting

```bash
systemctl status wg-quick@proton
journalctl -u wg-quick@proton -n 50
wg show proton
cat /etc/wireguard/proton.conf   # must contain Table = off and PostUp = /usr/local/sbin/proton-up.sh
ip rule show; ip route show table 51821; iptables -t nat -S | grep proton
bash -x /usr/local/sbin/proton-up.sh   # verbose re-apply (SSH safe)
```

*No handshake* → endpoint blocked (UDP 51820 must be reachable *outbound* from the server), or time skewed (`timedatectl`). Try `wg-quick down proton; wg-quick up proton`.
*Client still shows server IP* → policy rules not hit: `ip rule show` must have `from 192.168.43.0/24 lookup 51821`. Re-run `proton.sh`.
*Proton rejects the connection* → free account already connected elsewhere (1-device limit), or the profile PrivateKey no longer matches the account — download a fresh `.conf`.
*SSH risk* → the script never replaces the main default route; verify `ip route show default` is via `$NET_IFACE`, not `proton`.

## Uninstall

```bash
sudo bash extras/proton.sh uninstall
# config left at /etc/wireguard/proton.conf - delete manually if desired
```

## Performance notes

* Kernel WireGuard > userspace Proton clients (lower CPU, GRO, no extra TUN).
* MTU 1420 matches ProtonVPN's typical tunnel MTU; MSS clamp avoids fragmentation — keep `net.ipv4.tcp_congestion_control=bbr` and `fq` from the base VPN sysctl.
* `PersistentKeepalive = 25` keeps the NAT mapping alive through ProtonVPN's double-NAT.
