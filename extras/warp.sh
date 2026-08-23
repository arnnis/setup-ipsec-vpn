#!/bin/bash
#
# WARP integration for setup-ipsec-vpn - Route IKEv2/L2TP/XAuth clients via Cloudflare WARP
# Uses kernel WireGuard for best performance, policy routing keeps SSH and IPsec control traffic on main route
#
# Copyright (C) 2026 - Based on hwdsl2/setup-ipsec-vpn (CC BY-SA 3.0)
#
# Usage:
#   sudo bash warp.sh                # install / enable (idempotent)
#   sudo bash warp.sh uninstall      # disable and remove WARP routing (VPN stays via direct)
#   sudo bash warp.sh status         # show status
#   sudo bash warp.sh restart        # restart warp (re-apply routing/iptables)
#
# Env vars (optional):
#   WARP_CONF_SRC=/path/to/wgcf-profile.conf   # custom source profile to import
#   WARP_TABLE=51820                           # routing table id (default 51820)
#   WARP_IF=warp                               # WireGuard interface name (default warp)
#   WARP_ENDPOINT=engage.cloudflareclient.com:2408  # override endpoint
#
# Notes:
# - Server's own traffic (SSH, apt, etc) stays on main table via default route on NET_IFACE.
# - Only VPN client subnets (XAUTH_NET + L2TP_NET + IPv6 NET if enabled) are policy-routed via WARP.
# - WARP endpoint IP is pinned with a /32 route via NET_IFACE to avoid routing loop.
# - Table=off in warp.conf prevents wg-quick from hijacking main default route (keeps SSH reachable).
# - Performance: kernel WireGuard, MTU 1280, MSS clamp, BBR/fq preserved from base VPN sysctl.
#
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
set -e

WARP_IF="${WARP_IF:-warp}"
WARP_TABLE="${WARP_TABLE:-51820}"
WARP_CONF="/etc/wireguard/${WARP_IF}.conf"
WARP_UP_HELPER="/usr/local/sbin/warp-up.sh"
WARP_DOWN_HELPER="/usr/local/sbin/warp-down.sh"
WARP_ENDPOINT_DEFAULT="engage.cloudflareclient.com:2408"
WARP_ENDPOINT="${WARP_ENDPOINT:-$WARP_ENDPOINT_DEFAULT}"

SYS_DT=$(date +%F-%T | tr ':' '_')

exiterr() { echo "Error: $1" >&2; exit 1; }
bigecho() { echo "## $1"; }
conf_bk() { /bin/cp -f "$1" "$1.old-$SYS_DT" 2>/dev/null || true; }

check_root() {
  [ "$(id -u)" = 0 ] || exiterr "Script must be run as root. Try 'sudo bash $0'"
}

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_os() {
  rh_file="/etc/redhat-release"
  if [ -f "$rh_file" ]; then
    os_type=centos
    grep -q "Red Hat" "$rh_file" && os_type=rhel
    [ -f /etc/oracle-release ] && os_type=ol
    grep -qi rocky "$rh_file" && os_type=rocky
    grep -qi alma "$rh_file" && os_type=alma
  elif grep -qs "Amazon Linux release 2 " /etc/system-release; then
    os_type=amzn
  else
    os_type=$(lsb_release -si 2>/dev/null || true)
    [ -z "$os_type" ] && [ -f /etc/os-release ] && os_type=$(. /etc/os-release && printf '%s' "$ID")
    case $os_type in
      [Uu]buntu) os_type=ubuntu ;;
      [Dd]ebian|[Kk]ali|[Rr]aspbian) os_type=debian ;;
      [Aa]lpine) os_type=alpine ;;
      *) os_type=ubuntu ;;
    esac
  fi
}

detect_iface() {
  def_iface=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
  [ -z "$def_iface" ] && def_iface=$(route 2>/dev/null | grep -m 1 '^default' | grep -o '[^ ]*$')
  [ -z "$def_iface" ] && def_iface=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -Po '(?<=dev )(\S+)')
  if [ -z "$def_iface" ]; then
    eth0_state=$(cat "/sys/class/net/eth0/operstate" 2>/dev/null || true)
    if [ -n "$eth0_state" ] && [ "$eth0_state" != "down" ]; then
      def_iface=eth0
    else
      exiterr "Could not detect default network interface."
    fi
  fi
  NET_IFACE="$def_iface"
  # gateway for endpoint bypass
  GW=$(ip -4 route show default dev "$NET_IFACE" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -n1)
  [ -z "$GW" ] && GW=$(ip -4 route get 1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -n1)
  bigecho "Detected NET_IFACE=$NET_IFACE GW=${GW:-unknown}"
}

detect_subnets() {
  L2TP_NET=${VPN_L2TP_NET:-'192.168.42.0/24'}
  XAUTH_NET=${VPN_XAUTH_NET:-'192.168.43.0/24'}
  IP6_NET=${VPN_IP6_NET:-'fddd:500:500:500::/64'}
  # try to read actual from /etc/ipsec.conf if custom
  if [ -s /etc/ipsec.conf ]; then
    vipr=$(grep "virtual-private=" /etc/ipsec.conf 2>/dev/null || true)
    if printf '%s' "$vipr" | grep -q "192.168"; then
      # parse !L2TP,!XAUTH
      cand1=$(printf '%s' "$vipr" | cut -f2 -d '!' | cut -f1 -d ',' | tr -d ' %')
      cand2=$(printf '%s' "$vipr" | cut -f3 -d '!' | cut -f1 -d ',' | tr -d ' %')
      # validate cidr
      if printf '%s' "$cand1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'; then
        L2TP_NET="$cand1"
      fi
      if printf '%s' "$cand2" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'; then
        XAUTH_NET="$cand2"
      fi
    fi
    # also check ikev2 rightaddresspool may differ but we cover via XAUTH_NET
  fi
  # detect if IPv6 enabled (ip6tables rules or ip6)
  HAS_IP6=0
  if grep -qs "hwdsl2 VPN script" /etc/sysctl.conf 2>/dev/null && grep -q "net.ipv6.conf.all.forwarding = 1" /etc/sysctl.conf 2>/dev/null; then
    HAS_IP6=1
  fi
  if [ -f /etc/ip6tables.rules ] || [ -f /etc/sysconfig/ip6tables ]; then
    HAS_IP6=1
  fi
  bigecho "VPN subnets: L2TP_NET=$L2TP_NET XAUTH_NET=$XAUTH_NET IP6_NET=$IP6_NET HAS_IP6=$HAS_IP6"
}

check_vpn_installed() {
  if ! grep -qs "hwdsl2 VPN script" /etc/sysctl.conf 2>/dev/null; then
    echo "Warning: hwdsl2 VPN script marker not found in /etc/sysctl.conf - VPN may not be installed." >&2
  fi
  if [ ! -f /etc/ipsec.conf ]; then
    exiterr "IPsec config /etc/ipsec.conf not found. Install VPN first (https://github.com/hwdsl2/setup-ipsec-vpn)"
  fi
}

install_wireguard_pkgs() {
  bigecho "Installing WireGuard tools..."
  if [ "$os_type" = "ubuntu" ] || [ "$os_type" = "debian" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -yqq update || apt-get -yqq update || true
    apt-get -yqq install wireguard-tools iproute2 iptables dnsutils curl wget kmod 2>&1 >/dev/null || apt-get -yqq install wireguard-tools iproute2 iptables 2>&1 >/dev/null || {
      # fallback for older releases where package is wireguard
      apt-get -yqq install wireguard 2>&1 >/dev/null || true
    }
    # ensure kernel module available (built-in on 5.6+), else try linux-modules-extra
    if ! modprobe wireguard 2>/dev/null && ! ip link help 2>&1 | grep -q wireguard; then
      bigecho "Trying to install kernel WireGuard support..."
      apt-get -yqq install "linux-modules-extra-$(uname -r)" 2>&1 >/dev/null || true
      modprobe wireguard 2>/dev/null || true
    fi
  elif [ "$os_type" = "alpine" ]; then
    apk add -U -q wireguard-tools iptables ip6tables iproute2 curl wget 2>&1 >/dev/null || exiterr "'apk add wireguard-tools' failed"
    modprobe wireguard 2>/dev/null || true
  else
    # RHEL family
    if ! command -v wg >/dev/null 2>&1; then
      # try epel
      if [ "$os_type" = "amzn" ]; then
        yum -y -q install wireguard-tools iproute iptables 2>&1 >/dev/null || yum -y -q install wireguard-tools 2>&1 >/dev/null || true
      else
        yum -y -q install epel-release 2>&1 >/dev/null || true
        yum -y -q install wireguard-tools iproute iptables kmod-wireguard 2>&1 >/dev/null || yum -y -q install wireguard-tools 2>&1 >/dev/null || true
      fi
    fi
    modprobe wireguard 2>/dev/null || true
  fi
  command -v wg >/dev/null 2>&1 || exiterr "WireGuard 'wg' not found after install."
  command -v wg-quick >/dev/null 2>&1 || {
    echo "Warning: wg-quick not found, but wg exists. Will use wg manually." >&2
  }
  bigecho "WireGuard tools installed: $(wg --version 2>&1 | head -n1)"
}

get_wgcf_binary() {
  if command -v wgcf >/dev/null 2>&1; then
    echo "wgcf already installed: $(wgcf --version 2>&1 | head -n1)"
    return 0
  fi
  bigecho "Installing wgcf..."
  arch=$(uname -m)
  case $arch in
    x86_64|amd64) wgcf_arch="amd64" ;;
    aarch64|arm64) wgcf_arch="arm64" ;;
    armv7l|armv6l) wgcf_arch="arm" ;;
    *) wgcf_arch="amd64" ;;
  esac
  # latest known stable 2.2.27 fallback
  WGCF_VER="2.2.27"
  # try to fetch latest via github api (best effort)
  latest=$(curl -m 10 -fsL "https://api.github.com/repos/ViRb3/wgcf/releases/latest" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -n1 | cut -d'"' -f4 | tr -d 'v')
  [ -n "$latest" ] && WGCF_VER="$latest"
  url="https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VER}/wgcf_${WGCF_VER}_linux_${wgcf_arch}"
  tmp="/tmp/wgcf"
  if wget -t 2 -T 15 -qO "$tmp" "$url" 2>/dev/null || curl -m 15 -fsL "$url" -o "$tmp" 2>/dev/null; then
    chmod +x "$tmp"
    mv -f "$tmp" /usr/local/bin/wgcf
    echo "wgcf installed: $(wgcf --version 2>&1 | head -n1)"
  else
    echo "Warning: could not download wgcf $WGCF_VER for $wgcf_arch" >&2
    return 1
  fi
}

resolve_endpoint_ip() {
  ep_host=$(printf '%s' "$WARP_ENDPOINT" | cut -d: -f1 | tr -d ' ')
  ep_port=$(printf '%s' "$WARP_ENDPOINT" | cut -d: -f2 | tr -d ' ')
  [ -z "$ep_port" ] && ep_port=2408
  # try getent, then dig, then hardcode cloudflare
  ep_ip=""
  if command -v getent >/dev/null 2>&1; then
    ep_ip=$(getent ahosts "$ep_host" 2>/dev/null | awk '{print $1}' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1)
  fi
  if [ -z "$ep_ip" ] && command -v dig >/dev/null 2>&1; then
    ep_ip=$(dig +short A "$ep_host" 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1)
  fi
  if [ -z "$ep_ip" ] && command -v host >/dev/null 2>&1; then
    ep_ip=$(host "$ep_host" 2>/dev/null | awk '/has address/ {print $4}' | head -n1)
  fi
  # cloudflare engage fallback IPs (anycast)
  if [ -z "$ep_ip" ]; then
    ep_ip="162.159.193.1"
    echo "Warning: could not resolve $ep_host, using fallback $ep_ip" >&2
  fi
  ENDPOINT_IP="$ep_ip"
  ENDPOINT_HOST="$ep_host"
  ENDPOINT_PORT="$ep_port"
  bigecho "WARP endpoint $ENDPOINT_HOST:$ENDPOINT_PORT -> $ENDPOINT_IP"
}

ensure_warp_conf() {
  bigecho "Preparing $WARP_CONF ..."
  mkdir -p /etc/wireguard
  chmod 700 /etc/wireguard 2>/dev/null || true

  SRC=""
  # 1) explicit env
  if [ -n "$WARP_CONF_SRC" ] && [ -f "$WARP_CONF_SRC" ]; then
    SRC="$WARP_CONF_SRC"
  # 2) existing warp conf already valid
  elif [ -s "$WARP_CONF" ] && grep -q "PrivateKey" "$WARP_CONF"; then
    SRC="$WARP_CONF"
    bigecho "Existing $WARP_CONF found - will patch it for policy routing."
  # 3) search common locations for wgcf-profile
  else
    for cand in "./wgcf-profile.conf" "/opt/wgcf-profile.conf" "/etc/wireguard/wgcf-profile.conf" "/root/wgcf-profile.conf" "/opt/src/wgcf-profile.conf" "$PWD/wgcf-profile.conf"; do
      if [ -s "$cand" ] && grep -q "PrivateKey" "$cand"; then SRC="$cand"; bigecho "Found profile source $cand"; break; fi
    done
  fi

  # 3b) search wgcf-account.toml -> generate profile if found
  if [ -z "$SRC" ]; then
    for acct in "./wgcf-account.toml" "/opt/wgcf-account.toml" "/etc/wireguard/wgcf-account.toml"; do
      if [ -s "$acct" ]; then
        bigecho "Found $acct - generating wgcf profile..."
        get_wgcf_binary || true
        if command -v wgcf >/dev/null 2>&1; then
          ( cd "$(dirname "$acct")" && wgcf generate 2>&1 | tail -n 20)
          for cand2 in "$(dirname "$acct")/wgcf-profile.conf" "./wgcf-profile.conf" "/opt/wgcf-profile.conf"; do
            [ -s "$cand2" ] && SRC="$cand2" && break
          done
        fi
        break
      fi
    done
  fi

  # 4) if still no SRC, try wgcf register flow
  if [ -z "$SRC" ]; then
    bigecho "No existing WARP profile - will create one via wgcf register..."
    get_wgcf_binary
    tmpdir=$(mktemp -d)
    (
      cd "$tmpdir"
      wgcf register --accept-tos 2>&1 | tail -n 20
      wgcf generate 2>&1 | tail -n 20
      if [ -s "wgcf-profile.conf" ]; then
        cp -f "wgcf-profile.conf" /etc/wireguard/wgcf-profile.conf
        SRC="/etc/wireguard/wgcf-profile.conf"
      fi
    )
    rm -rf "$tmpdir" 2>/dev/null || true
    if [ -z "$SRC" ] || [ ! -s "$SRC" ]; then
      # search again
      [ -s "/etc/wireguard/wgcf-profile.conf" ] && SRC="/etc/wireguard/wgcf-profile.conf"
    fi
  fi

  [ -n "$SRC" ] && [ -s "$SRC" ] || exiterr "Could not find or generate WARP WireGuard profile. Provide one via WARP_CONF_SRC=/path/to/wgcf-profile.conf"

  # Now patch SRC into proper warp.conf with Table=off and helpers
  bigecho "Creating $WARP_CONF from $SRC (Table=off, MTU 1280, policy routing safe)"
  conf_bk "$WARP_CONF"
  # extract keys
  PK=$(grep -i "PrivateKey" "$SRC" | cut -d= -f2 | tr -d ' ' | head -n1)
  ADDR4=$(grep -i "Address" "$SRC" | tr ',' '\n' | grep -E '172\.16\.' | head -n1 | cut -d= -f2 | tr -d ' ' 2>/dev/null || grep "Address" "$SRC" | head -n1 | cut -d= -f2 | tr -d ' ' | cut -d',' -f1)
  # more robust: get all Address lines
  ADDR_LINE=$(grep -i "^Address" "$SRC" | head -n1)
  # if Address contains both v4 and v6, split
  ADDRS=$(printf '%s' "$ADDR_LINE" | cut -d= -f2 | tr -d ' ')
  ADDR_V4=$(printf '%s' "$ADDRS" | tr ',' '\n' | grep -E '^[0-9].*\/32' | head -n1)
  ADDR_V6=$(printf '%s' "$ADDRS" | tr ',' '\n' | grep -E ':' | head -n1)
  [ -z "$ADDR_V4" ] && ADDR_V4=$(printf '%s' "$ADDRS" | tr ',' '\n' | head -n1)

  PUBKEY=$(grep -i "PublicKey" "$SRC" | cut -d= -f2 | tr -d ' ' | head -n1)
  ENDPOINT_SRC=$(grep -i "Endpoint" "$SRC" | cut -d= -f2 | tr -d ' ' | head -n1)
  [ -n "$ENDPOINT_SRC" ] && WARP_ENDPOINT="$ENDPOINT_SRC"
  ALLOWED=$(grep -i "AllowedIPs" "$SRC" | head -n1 | cut -d= -f2 | tr -d ' ' )
  [ -z "$ALLOWED" ] && ALLOWED="0.0.0.0/0,::/0"

  [ -n "$PK" ] || exiterr "PrivateKey not found in $SRC"
  [ -n "$PUBKEY" ] || exiterr "PublicKey not found in $SRC"

  # Determine DNS - we keep but don't apply via resolvconf if possible
  # We'll keep MTU 1280 as warp standard for performance (avoids frag)
  cat > "$WARP_CONF" <<EOF
[Interface]
PrivateKey = $PK
Address = $ADDR_V4
EOF
  if [ -n "$ADDR_V6" ] && [ "$ADDR_V6" != "$ADDR_V4" ]; then
    echo "Address = $ADDR_V6" >> "$WARP_CONF"
  fi
  cat >> "$WARP_CONF" <<EOF
MTU = 1280
Table = off
PostUp = $WARP_UP_HELPER
PreDown = $WARP_DOWN_HELPER
# DNS intentionally not set here to avoid overwriting host resolv.conf.
# If you need host DNS via WARP, add: DNS = 1.1.1.1

[Peer]
PublicKey = $PUBKEY
AllowedIPs = $ALLOWED
Endpoint = $WARP_ENDPOINT
PersistentKeepalive = 25
EOF
  chmod 600 "$WARP_CONF"
  bigecho "Wrote $WARP_CONF (Table=off, PostUp helper, MTU 1280)"
  # show
  grep -v "PrivateKey" "$WARP_CONF" || true
}

create_helpers() {
  bigecho "Creating helper scripts $WARP_UP_HELPER and $WARP_DOWN_HELPER ..."
  # Up helper
  cat > "$WARP_UP_HELPER" <<EOS
#!/bin/bash
# Auto-generated by warp.sh - DO NOT EDIT MANUALLY
set -e
WARP_IF="${WARP_IF}"
WARP_TABLE="${WARP_TABLE}"
NET_IFACE_DETECTED="$NET_IFACE"
L2TP_NET="$L2TP_NET"
XAUTH_NET="$XAUTH_NET"
IP6_NET="$IP6_NET"
HAS_IP6="$HAS_IP6"
WARP_ENDPOINT="$WARP_ENDPOINT"
GW="$GW"
ENDPOINT_IP="$ENDPOINT_IP"

check_ip() { printf '%s' "\$1" | grep -Eq '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\$'; }

# Re-detect if values stale (GW may change after reboot)
if [ -z "\$GW" ] || ! check_ip "\$GW" 2>/dev/null; then
  GW=\$(ip -4 route show default dev "\$NET_IFACE_DETECTED" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="via") print \$(i+1)}' | head -n1)
  [ -z "\$GW" ] && GW=\$(ip -4 route get 1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="via") print \$(i+1)}' | head -n1)
fi
if [ -z "\$ENDPOINT_IP" ]; then
  ep_host=\$(printf '%s' "\$WARP_ENDPOINT" | cut -d: -f1)
  ENDPOINT_IP=\$(getent ahosts "\$ep_host" 2>/dev/null | awk '{print \$1}' | grep -E '^([0-9]{1,3}\\.){3}[0-9]{1,3}\$' | head -n1)
  [ -z "\$ENDPOINT_IP" ] && ENDPOINT_IP=\$(dig +short A "\$ep_host" 2>/dev/null | head -n1)
  [ -z "\$ENDPOINT_IP" ] && ENDPOINT_IP="162.159.193.1"
fi

# 1) Ensure endpoint bypass via main table (avoid loop)
if [ -n "\$ENDPOINT_IP" ] && [ -n "\$GW" ] && check_ip "\$GW"; then
  ip route replace "\$ENDPOINT_IP/32" via "\$GW" dev "\$NET_IFACE_DETECTED" 2>/dev/null || ip route add "\$ENDPOINT_IP/32" via "\$GW" dev "\$NET_IFACE_DETECTED" 2>/dev/null || true
fi

# 2) Policy routing table for VPN clients only (keeps SSH/host on main)
ip route replace default dev "\$WARP_IF" table "\$WARP_TABLE" 2>/dev/null || ip route add default dev "\$WARP_IF" table "\$WARP_TABLE" 2>/dev/null || true
if [ "\$HAS_IP6" = 1 ]; then
  ip -6 route replace default dev "\$WARP_IF" table "\$WARP_TABLE" 2>/dev/null || ip -6 route add default dev "\$WARP_IF" table "\$WARP_TABLE" 2>/dev/null || true
fi

# 3) Rules: only FROM VPN subnets -> WARP (SSH stays on main)
for net in "\$L2TP_NET" "\$XAUTH_NET"; do
  [ -z "\$net" ] && continue
  ip rule del from "\$net" table "\$WARP_TABLE" 2>/dev/null || true
  ip rule add from "\$net" table "\$WARP_TABLE" priority 51820 2>/dev/null || ip rule add from "\$net" lookup "\$WARP_TABLE" 2>/dev/null || true
done
if [ "\$HAS_IP6" = 1 ] && [ -n "\$IP6_NET" ]; then
  ip -6 rule del from "\$IP6_NET" table "\$WARP_TABLE" 2>/dev/null || true
  ip -6 rule add from "\$IP6_NET" table "\$WARP_TABLE" priority 51820 2>/dev/null || ip -6 rule add from "\$IP6_NET" lookup "\$WARP_TABLE" 2>/dev/null || true
fi

# 4) Sysctl for warp interface (performance & no rp_filter drop)
sysctl -w "net.ipv4.conf.\$WARP_IF.rp_filter=0" >/dev/null 2>&1 || true
sysctl -w "net.ipv4.conf.\$WARP_IF.send_redirects=0" >/dev/null 2>&1 || true
sysctl -w "net.ipv4.conf.all.rp_filter=0" >/dev/null 2>&1 || true

# 5) iptables NAT via warp (MASQUERADE) - idempotent
if command -v iptables >/dev/null 2>&1; then
  for net in "\$L2TP_NET" "\$XAUTH_NET"; do
    [ -z "\$net" ] && continue
    # check if rule exists
    if ! iptables -t nat -C POSTROUTING -s "\$net" -o "\$WARP_IF" -j MASQUERADE 2>/dev/null; then
      iptables -t nat -I POSTROUTING 1 -s "\$net" -o "\$WARP_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "\$net" -o "\$WARP_IF" -j MASQUERADE 2>/dev/null || true
    fi
  done
  # MSS clamp for warp (both directions) - huge perf win, avoids PMTU blackhole
  for chain in FORWARD; do
    if ! iptables -t mangle -C "\$chain" -o "\$WARP_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
      iptables -t mangle -A "\$chain" -o "\$WARP_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    fi
    if ! iptables -t mangle -C "\$chain" -i "\$WARP_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
      iptables -t mangle -A "\$chain" -i "\$WARP_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    fi
  done
  # FORWARD accept for warp (if default DROP at end)
  # Insert near top before final DROP - we use -I to be safe
  for net in "\$L2TP_NET" "\$XAUTH_NET"; do
    if ! iptables -C FORWARD -s "\$net" -o "\$WARP_IF" -j ACCEPT 2>/dev/null; then
      iptables -I FORWARD 1 -s "\$net" -o "\$WARP_IF" -j ACCEPT 2>/dev/null || true
    fi
    if ! iptables -C FORWARD -i "\$WARP_IF" -d "\$net" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
      iptables -I FORWARD 2 -i "\$WARP_IF" -d "\$net" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    fi
  done
  # also allow ppp+ -> warp
  if ! iptables -C FORWARD -i ppp+ -o "\$WARP_IF" -j ACCEPT 2>/dev/null; then
    iptables -I FORWARD 3 -i ppp+ -o "\$WARP_IF" -j ACCEPT 2>/dev/null || true
  fi
  if ! iptables -C FORWARD -i "\$WARP_IF" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    iptables -I FORWARD 4 -i "\$WARP_IF" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi
fi

# nftables fallback (EL10) - if nft list contains warp, ensure rules exist
if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q "hwdsl2"; then
  # try to add via nft if iptables-nft not enough (best effort, non-fatal)
  for net in "\$L2TP_NET" "\$XAUTH_NET"; do
    nft add rule inet nat postrouting ip saddr "\$net" oifname "\$WARP_IF" masquerade 2>/dev/null || true
  done
fi

# IPv6 NAT if enabled
if [ "\$HAS_IP6" = 1 ] && command -v ip6tables >/dev/null 2>&1; then
  if ! ip6tables -t nat -C POSTROUTING -s "\$IP6_NET" -o "\$WARP_IF" -j MASQUERADE 2>/dev/null; then
    ip6tables -t nat -I POSTROUTING 1 -s "\$IP6_NET" -o "\$WARP_IF" -j MASQUERADE 2>/dev/null || true
  fi
fi

echo "warp-up: routing via \$WARP_IF (table \$WARP_TABLE) for \$L2TP_NET, \$XAUTH_NET (SSH bypassed via \$NET_IFACE_DETECTED)"
EOS
  chmod +x "$WARP_UP_HELPER"

  cat > "$WARP_DOWN_HELPER" <<EOS
#!/bin/bash
set -e
WARP_IF="${WARP_IF}"
WARP_TABLE="${WARP_TABLE}"
L2TP_NET="$L2TP_NET"
XAUTH_NET="$XAUTH_NET"
IP6_NET="$IP6_NET"
HAS_IP6="$HAS_IP6"
WARP_ENDPOINT="$WARP_ENDPOINT"
ENDPOINT_IP="$ENDPOINT_IP"
NET_IFACE_DETECTED="$NET_IFACE"

# remove policy rules
for net in "\$L2TP_NET" "\$XAUTH_NET"; do
  ip rule del from "\$net" table "\$WARP_TABLE" 2>/dev/null || true
done
if [ "\$HAS_IP6" = 1 ]; then
  ip -6 rule del from "\$IP6_NET" table "\$WARP_TABLE" 2>/dev/null || true
fi
ip route flush table "\$WARP_TABLE" 2>/dev/null || true
# remove endpoint bypass (optional keep, but clean)
# ip route del "\$ENDPOINT_IP/32" via "$GW" dev "\$NET_IFACE_DETECTED" 2>/dev/null || true

# remove iptables warp rules
if command -v iptables >/dev/null 2>&1; then
  for net in "\$L2TP_NET" "\$XAUTH_NET"; do
    iptables -t nat -D POSTROUTING -s "\$net" -o "\$WARP_IF" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -s "\$net" -o "\$WARP_IF" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "\$WARP_IF" -d "\$net" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  done
  iptables -t mangle -D FORWARD -o "\$WARP_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  iptables -t mangle -D FORWARD -i "\$WARP_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  iptables -D FORWARD -i ppp+ -o "\$WARP_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "\$WARP_IF" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
fi
if [ "\$HAS_IP6" = 1 ] && command -v ip6tables >/dev/null 2>&1; then
  ip6tables -t nat -D POSTROUTING -s "\$IP6_NET" -o "\$WARP_IF" -j MASQUERADE 2>/dev/null || true
fi
echo "warp-down: cleaned table \$WARP_TABLE and iptables for \$WARP_IF"
EOS
  chmod +x "$WARP_DOWN_HELPER"
  bigecho "Helpers created."
}

enable_systemd() {
  if command -v systemctl >/dev/null 2>&1; then
    bigecho "Enabling wg-quick@${WARP_IF} via systemd..."
    systemctl enable "wg-quick@${WARP_IF}" 2>/dev/null || true
    # ensure we have a drop-in to restart warp after network is ready (avoid SSH race)
    mkdir -p /etc/systemd/system/"wg-quick@${WARP_IF}.service.d"
    cat > /etc/systemd/system/"wg-quick@${WARP_IF}.service.d/override.conf" <<EOF
[Unit]
After=network-online.target nss-lookup.target
Wants=network-online.target
# Ensure ipsec starts after warp so policy routing is ready; but don't fail if ipsec not yet
[Service]
# Safety: don't kill SSH on failure
Restart=on-failure
RestartSec=5
EOF
    systemctl daemon-reload
    # bring up now - use helper to ensure endpoint bypass first
    bigecho "Starting WARP interface $WARP_IF ..."
    # Pre-add endpoint bypass before wg-quick brings up (avoids loop during handshake)
    if [ -n "$ENDPOINT_IP" ] && [ -n "$GW" ]; then
      ip route replace "$ENDPOINT_IP/32" via "$GW" dev "$NET_IFACE" 2>/dev/null || ip route add "$ENDPOINT_IP/32" via "$GW" dev "$NET_IFACE" 2>/dev/null || true
    fi
    wg-quick down "$WARP_IF" 2>/dev/null || true
    if wg-quick up "$WARP_IF" 2>&1 | tee /tmp/wg-quick.log; then
      bigecho "WARP $WARP_IF up."
    else
      cat /tmp/wg-quick.log >&2
      exiterr "wg-quick up $WARP_IF failed. Check $WARP_CONF and 'wg show' / 'journalctl -u wg-quick@${WARP_IF}'"
    fi
    # verify PostUp ran
    sleep 1
    "$WARP_UP_HELPER" || true
  elif [ "$os_type" = "alpine" ]; then
    bigecho "Enabling WARP via OpenRC..."
    rc-update add "wg-quick.${WARP_IF}" default 2>/dev/null || {
      # fallback: create init script
      ln -sf /etc/init.d/wg-quick "/etc/init.d/wg-quick.${WARP_IF}" 2>/dev/null || true
      rc-update add "wg-quick.${WARP_IF}" default 2>/dev/null || true
    }
    wg-quick up "$WARP_IF" 2>/dev/null || wg-quick up "$WARP_IF"
  else
    bigecho "No systemd/OpenRC found - bringing up WARP manually..."
    wg-quick up "$WARP_IF" || exiterr "wg-quick up failed"
  fi
}

persist_iptables() {
  # Ensure warp iptables survive reboot via our helper (systemd PostUp does it)
  # Also optionally save to persistent file if exists, so first packets before warp up still have base rules
  if [ -f /etc/iptables.rules ]; then
    bigecho "Persisting iptables: adding warp rules to /etc/iptables.rules for next reboot fallback"
    # We don't overwrite; helper will re-add on boot after warp up. Just ensure file has comment for warp
    if ! grep -q "warp" /etc/iptables.rules 2>/dev/null; then
      # append a comment; actual rules will be re-added by warp-up
      echo "# WARP warp rules managed by $WARP_UP_HELPER (table $WARP_TABLE)" >> /etc/iptables.rules || true
    fi
  fi
  if [ -f /etc/sysconfig/iptables ] && ! grep -q "warp" /etc/sysconfig/iptables 2>/dev/null; then
    echo "# WARP warp rules managed by $WARP_UP_HELPER" >> /etc/sysconfig/iptables || true
  fi
}

do_status() {
  echo "=== WARP Status ==="
  echo "Interface: $WARP_IF  Table: $WARP_TABLE  Conf: $WARP_CONF"
  echo "NET_IFACE: ${NET_IFACE:-unknown}  L2TP_NET: ${L2TP_NET:-?}  XAUTH_NET: ${XAUTH_NET:-?}"
  echo
  echo "--- wg show ---"
  wg show "$WARP_IF" 2>&1 || echo "wg $WARP_IF not up"
  echo
  echo "--- ip link ---"
  ip link show dev "$WARP_IF" 2>&1 || echo "no link $WARP_IF"
  echo
  echo "--- ip rule (should show from L2TP/XAUTH -> table $WARP_TABLE) ---"
  ip rule show 2>&1 | cat
  ip -6 rule show 2>&1 | cat || true
  echo
  echo "--- ip route table $WARP_TABLE ---"
  ip route show table "$WARP_TABLE" 2>&1 | cat
  ip -6 route show table "$WARP_TABLE" 2>&1 | cat || true
  echo
  echo "--- endpoint bypass ---"
  if [ -n "$ENDPOINT_IP" ]; then
    ip route get "$ENDPOINT_IP" 2>&1 | cat
  else
    ep_host=$(grep Endpoint "$WARP_CONF" 2>/dev/null | cut -d= -f2 | cut -d: -f1 | tr -d ' ')
    [ -n "$ep_host" ] && ip route get "$(getent ahosts "$ep_host" 2>/dev/null | awk '{print $1}' | head -n1)" 2>&1 | cat || true
  fi
  echo
  echo "--- iptables NAT (warp) ---"
  iptables -t nat -S 2>&1 | grep -i warp || iptables -t nat -S 2>&1 | grep -E "192\.168\.4(2|3)" | head -n 20
  echo
  echo "--- iptables mangle MSS clamp ---"
  iptables -t mangle -S 2>&1 | grep -i "TCPMSS.*warp\|clamp" | head -n 20
  echo
  echo "--- ping test via warp (VPN client subnet simulation) ---"
  # test egress IP via warp using policy routing simulation: ping with source from XAUTH_NET via warp table
  if ip route show table "$WARP_TABLE" | grep -q "dev $WARP_IF"; then
    echo "WARP table has default via $WARP_IF - likely working."
    # try curl via warp interface if available
    if command -v curl >/dev/null 2>&1; then
      echo "Trying curl --interface $WARP_IF https://ifconfig.co (5s timeout) ..."
      timeout 5 curl --interface "$WARP_IF" -s https://ifconfig.co 2>&1 | head -n 5 || echo "curl via $WARP_IF failed (maybe firewall) - check 'wg show' handshake"
    fi
  else
    echo "WARP table missing default route!"
  fi
  echo
  echo "--- SSH safety check ---"
  echo "Main default route (should be via $NET_IFACE, NOT warp):"
  ip -4 route show default 2>&1 | cat
  if ip -4 route show default | grep -q "dev $WARP_IF"; then
    echo "WARNING: main default via $WARP_IF -> SSH may be at risk! Table=off should prevent this."
  else
    echo "OK: main default stays via $NET_IFACE (SSH safe)"
  fi
}

do_uninstall() {
  bigecho "Disabling WARP routing (VPN will revert to direct)..."
  # bring down wg interface
  if ip link show dev "$WARP_IF" >/dev/null 2>&1; then
    wg-quick down "$WARP_IF" 2>/dev/null || ip link del "$WARP_IF" 2>/dev/null || true
  fi
  # clean helpers' rules (try)
  if [ -x "$WARP_DOWN_HELPER" ]; then
    "$WARP_DOWN_HELPER" 2>/dev/null || true
  else
    # manual clean
    for net in "$L2TP_NET" "$XAUTH_NET"; do
      ip rule del from "$net" table "$WARP_TABLE" 2>/dev/null || true
    done
    ip route flush table "$WARP_TABLE" 2>/dev/null || true
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable "wg-quick@${WARP_IF}" 2>/dev/null || true
    rm -f "/etc/systemd/system/wg-quick@${WARP_IF}.service.d/override.conf"
    systemctl daemon-reload 2>/dev/null || true
  fi
  bigecho "WARP disabled. Config kept at $WARP_CONF (remove manually if desired)."
  bigecho "VPN clients now go direct via $NET_IFACE again. No reboot needed."
}

do_install() {
  check_vpn_installed
  detect_iface
  detect_subnets
  install_wireguard_pkgs
  resolve_endpoint_ip
  ensure_warp_conf
  create_helpers
  enable_systemd
  persist_iptables
  echo
  bigecho "WARP enabled successfully!"
  echo "  Interface: $WARP_IF (table $WARP_TABLE)  Endpoint: $WARP_ENDPOINT ($ENDPOINT_IP)"
  echo "  VPN clients ($L2TP_NET, $XAUTH_NET) -> WARP -> Internet"
  echo "  Server/host & SSH -> direct via $NET_IFACE (safe)"
  echo "  MTU 1280 + MSS clamp + kernel WireGuard for max performance"
  echo
  do_status
  echo
  echo "To test: connect IKEv2 client, then visit https://ifconfig.co - should show Cloudflare WARP IP, not server IP"
  echo "Server SSH remains via $NET_IFACE gateway $GW"
  echo "Manage: sudo bash $0 status | uninstall | restart"
}

# main
check_root
check_os
# detect early for status/uninstall without full install
detect_iface >/dev/null 2>&1 || NET_IFACE="eth0"
detect_subnets >/dev/null 2>&1 || true
if [ -s "$WARP_CONF" ]; then
  WARP_ENDPOINT=$(grep -i "^Endpoint" "$WARP_CONF" | cut -d= -f2 | tr -d ' ' | head -n1)
  [ -z "$WARP_ENDPOINT" ] && WARP_ENDPOINT="$WARP_ENDPOINT_DEFAULT"
  resolve_endpoint_ip >/dev/null 2>&1 || true
fi

case "${1:-install}" in
  install|enable|on|up|"")
    do_install
    ;;
  uninstall|disable|off|down|remove)
    do_uninstall
    ;;
  status|show|check)
    do_status
    ;;
  restart|reload)
    bigecho "Restarting WARP..."
    if ip link show dev "$WARP_IF" >/dev/null 2>&1; then
      wg-quick down "$WARP_IF" 2>/dev/null || true
      sleep 1
      wg-quick up "$WARP_IF" 2>/dev/null || true
      "$WARP_UP_HELPER" 2>/dev/null || true
    else
      do_install
    fi
    do_status
    ;;
  *)
    echo "Usage: $0 [install|uninstall|status|restart]" >&2
    exit 1
    ;;
esac
