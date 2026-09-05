#!/bin/bash
#
# ProtonVPN (Free, WireGuard) integration for setup-ipsec-vpn
# Route IKEv2/L2TP/XAuth clients via a ProtonVPN Free WireGuard server
# Uses kernel WireGuard for best performance, policy routing keeps SSH and IPsec control traffic on main route
#
# Copyright (C) 2026 - Based on hwdsl2/setup-ipsec-vpn (CC BY-SA 3.0)
#
# Usage:
#   sudo PROTON_CONF_SRC=/path/to/protonvpn.conf bash proton.sh   # install / enable (idempotent)
#   sudo bash proton.sh                 # enable using an existing /etc/wireguard/proton.conf or uploaded profile
#   sudo bash proton.sh uninstall       # disable and remove ProtonVPN routing (VPN stays via direct)
#   sudo bash proton.sh status          # show status
#   sudo bash proton.sh restart         # restart (re-apply routing/iptables)
#
# Env vars (optional):
#   PROTON_CONF_SRC=/path/to/protonvpn-*.conf   # WireGuard config downloaded from ProtonVPN account portal
#   PROTON_TABLE=51821                          # routing table id (default 51821)
#   PROTON_IF=proton                            # WireGuard interface name (default proton)
#
# IMPORTANT - unlike Cloudflare WARP (anonymous wgcf registration), ProtonVPN WireGuard
# configs are bound to your Proton account (the PrivateKey is generated for you and is
# tied to your login). You must download one .conf from:
#     https://account.protonvpn.com/downloads  ->  "WireGuard configuration"
# (any FREE server location works) and make it available on the server, then point
# PROTON_CONF_SRC at it (or save it as /etc/wireguard/proton.conf).
#
# Notes:
# - Server's own traffic (SSH, apt, etc) stays on main table via default route on NET_IFACE.
# - Only VPN client subnets (XAUTH_NET + L2TP_NET + IPv6 NET if enabled AND the Proton
#   profile has an IPv6 address) are policy-routed via ProtonVPN. IPv6 is left on the
#   direct route when the profile is IPv4-only, so clients never blackhole on v6.
# - ProtonVPN endpoint is pinned with a /32 route via NET_IFACE to avoid routing loop.
# - Table=off in proton.conf prevents wg-quick from hijacking main default route (keeps SSH reachable).
# - Performance: kernel WireGuard, MTU 1420 (ProtonVPN standard) or source MTU, MSS clamp, BBR/fq preserved.
#
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
set -e

PROTON_IF="${PROTON_IF:-proton}"
PROTON_TABLE="${PROTON_TABLE:-51821}"
PROTON_CONF="/etc/wireguard/${PROTON_IF}.conf"
PROTON_UP_HELPER="/usr/local/sbin/proton-up.sh"
PROTON_DOWN_HELPER="/usr/local/sbin/proton-down.sh"
PROTON_ENDPOINT_DEFAULT=""   # no hardcoded Proton endpoint: taken from the downloaded .conf
PROTON_ENDPOINT="${PROTON_ENDPOINT:-$PROTON_ENDPOINT_DEFAULT}"

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
  fi
  # detect if IPv6 enabled on the base VPN (forwarding enabled + persistent ip6tables)
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

# Heuristic: is this conf a ProtonVPN WireGuard profile?
# (filename contains "proton" OR the peer endpoint mentions protonvpn OR the tunnel
#  address is Proton's well-known 10.2.0.2 / 10.3.0.2 / 10.4.0.2 NAT range)
is_proton_like() {
  local f="$1"
  [ -s "$f" ] || return 1
  grep -q "PrivateKey" "$f" || return 1
  case "$(basename "$f")" in
    *proton*) return 0 ;;
  esac
  grep -qi "protonvpn" "$f" && return 0
  grep -qE "(^|[^0-9])(10\.(2|3|4)\.0\.2/)" "$f" && return 0
  return 1
}

find_proton_source() {
  # 1) explicit env
  if [ -n "$PROTON_CONF_SRC" ]; then
    if [ -s "$PROTON_CONF_SRC" ] && grep -q "PrivateKey" "$PROTON_CONF_SRC"; then
      printf '%s' "$PROTON_CONF_SRC"
      return 0
    fi
    echo "Warning: PROTON_CONF_SRC=$PROTON_CONF_SRC not found or missing PrivateKey - ignoring." >&2
  fi
  # 2) existing proton conf already valid (idempotent re-run / manual placement)
  if [ -s "$PROTON_CONF" ] && grep -q "PrivateKey" "$PROTON_CONF"; then
    printf '%s' "$PROTON_CONF"
    return 0
  fi
  # 3) well-known upload paths
  for cand in "/opt/protonvpn-free.conf" "/opt/proton-free.conf" "/opt/proton.conf" \
              "/root/protonvpn-free.conf" "/root/proton-free.conf" "/root/proton.conf" \
              "/etc/wireguard/protonvpn-free.conf" "/etc/wireguard/protonvpn.conf" \
              "$PWD/protonvpn-free.conf" "$PWD/proton-free.conf" "$PWD/protonvpn.conf"; do
    if is_proton_like "$cand"; then
      bigecho "Found profile source $cand"
      printf '%s' "$cand"
      return 0
    fi
  done
  # 4) scan common dirs for any proton-looking *.conf
  for d in "$PWD" /root /opt /etc/wireguard; do
    [ -d "$d" ] || continue
    for f in "$d"/*.conf "$d"/proton*.conf; do
      [ -f "$f" ] || continue
      [ "$f" = "$PROTON_CONF" ] && continue
      if is_proton_like "$f"; then
        bigecho "Found profile source $f"
        printf '%s' "$f"
        return 0
      fi
    done
  done
  return 1
}

resolve_endpoint_ip() {
  [ -z "$PROTON_ENDPOINT" ] && return 0
  ep_authority="$PROTON_ENDPOINT"
  ep_host=""; ep_port="51820"
  case "$ep_authority" in
    \[*\]) # [v6]:port form - no IPv4 bypass pin possible
      ep_host=""
      ;;
    *:*) # hostname or IPv4 with port
      ep_host=$(printf '%s' "$ep_authority" | sed 's/:[0-9]*$//; s/^[[:space:]]*//; s/[[:space:]]*$//')
      ep_port=$(printf '%s' "$ep_authority" | grep -o ':[0-9]*$' | tr -d ':')
      ;;
    *) # no port
      ep_host=$(printf '%s' "$ep_authority" | tr -d ' ')
      ;;
  esac
  [ -z "$ep_port" ] && ep_port=51820
  ep_ip=""
  if check_ip "$ep_host" 2>/dev/null; then
    ep_ip="$ep_host"
  elif [ -n "$ep_host" ]; then
    if command -v getent >/dev/null 2>&1; then
      ep_ip=$(getent ahosts "$ep_host" 2>/dev/null | awk '{print $1}' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1)
    fi
    if [ -z "$ep_ip" ] && command -v dig >/dev/null 2>&1; then
      ep_ip=$(dig +short A "$ep_host" 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1)
    fi
    if [ -z "$ep_ip" ] && command -v host >/dev/null 2>&1; then
      ep_ip=$(host "$ep_host" 2>/dev/null | awk '/has address/ {print $4}' | head -n1)
    fi
  fi
  ENDPOINT_IP="$ep_ip"
  ENDPOINT_HOST="$ep_host"
  ENDPOINT_PORT="$ep_port"
  if [ -z "$ep_ip" ] && [ -n "$ep_host" ]; then
    echo "Warning: could not resolve ProtonVPN endpoint $ep_host - skipping bypass pin (non-fatal)." >&2
  elif [ -n "$ep_ip" ]; then
    bigecho "ProtonVPN endpoint ${ENDPOINT_HOST:-$ep_ip}:$ENDPOINT_PORT -> $ENDPOINT_IP"
  fi
}

# Read one key=value from the conf (keys used are unique per section in Proton configs)
cfget() { grep -i "$1" "$2" | head -n1 | cut -d= -f2- | tr -d ' \r'; }

ensure_proton_conf() {
  bigecho "Preparing $PROTON_CONF ..."
  mkdir -p /etc/wireguard
  chmod 700 /etc/wireguard 2>/dev/null || true

  local SRC
  SRC=$(find_proton_source) || SRC=""
  if [ -z "$SRC" ]; then
    echo
    echo "====================================================================" >&2
    echo "No ProtonVPN WireGuard profile found." >&2
    echo >&2
    echo "ProtonVPN (even the FREE plan) supports WireGuard, but configs are" >&2
    echo "account-bound (generated PrivateKey), so they cannot be auto-created" >&2
    echo "like Cloudflare WARP. Do this once:" >&2
    echo >&2
    echo "  1. Sign in at https://account.protonvpn.com/downloads" >&2
    echo "  2. Under 'WireGuard configuration', pick any FREE server" >&2
    echo "     (e.g. NL-FREE) and download the .conf file (it has a" >&2
    echo "     [Interface] PrivateKey section)." >&2
    echo "  3. Copy it to this server, e.g.:" >&2
    echo "     scp ~/Downloads/nl-free-01.protonvpn.net.conf root@YOUR_VPS:/root/" >&2
    echo "  4. Re-run:" >&2
    echo "     sudo PROTON_CONF_SRC=/root/nl-free-01.protonvpn.net.conf bash proton.sh" >&2
    echo "====================================================================" >&2
    exiterr "No ProtonVPN WireGuard profile available (see instructions above)."
  fi

  bigecho "Creating $PROTON_CONF from $SRC (Table=off, MTU, policy routing safe)"
  conf_bk "$PROTON_CONF"

  # --- [Interface] fields ---
  PK=$(cfget "^PrivateKey" "$SRC")
  if [ -n "$PK" ] && [ ${#PK} -eq 43 ]; then PK="${PK}="; fi
  # Collect every Address value (Proton may list v4+v6 comma separated or on separate lines)
  ADDRS=""
  while IFS= read -r al; do
    [ -z "$al" ] && continue
    val=$(printf '%s' "$al" | sed 's/^[Aa]ddress[[:space:]]*=[[:space:]]*//; s/[[:space:]]*$//' | tr -d '\r')
    [ -z "$val" ] && continue
    if [ -n "$ADDRS" ]; then ADDRS="$ADDRS, $val"; else ADDRS="$val"; fi
  done < <(grep -i "^Address" "$SRC")
  [ -z "$ADDRS" ] && exiterr "No Address found in $SRC (not a valid WireGuard profile?)"

  # Source MTU if the profile defines one, else ProtonVPN standard 1420
  MTU_SRC=$(cfget "^MTU" "$SRC")
  case "$MTU_SRC" in
    ''|*[!0-9]*) MTU_VAL=1420 ;;
    *) MTU_VAL="$MTU_SRC" ;;
  esac

  # --- [Peer] fields ---
  PUBKEY=$(cfget "^PublicKey" "$SRC")
  if [ -n "$PUBKEY" ] && [ ${#PUBKEY} -eq 43 ]; then PUBKEY="${PUBKEY}="; fi
  ALLOWED=$(cfget "^AllowedIPs" "$SRC")
  [ -z "$ALLOWED" ] && ALLOWED="0.0.0.0/0"
  ENDPOINT_SRC=$(cfget "^Endpoint" "$SRC")
  [ -n "$ENDPOINT_SRC" ] && PROTON_ENDPOINT="$ENDPOINT_SRC"
  KEEPALIVE_SRC=$(cfget "^PersistentKeepalive" "$SRC")
  case "$KEEPALIVE_SRC" in
    ''|*[!0-9]*) KEEPALIVE_VAL=25 ;;
    *) KEEPALIVE_VAL="$KEEPALIVE_SRC" ;;
  esac

  [ -n "$PK" ] || exiterr "PrivateKey not found in $SRC"
  [ -n "$PUBKEY" ] || exiterr "PublicKey not found in $SRC"
  [ -n "$PROTON_ENDPOINT" ] || exiterr "Endpoint not found in $SRC - download a fresh WireGuard config from ProtonVPN"

  # IPv6 via Proton only when the profile actually has a v6 address AND the base VPN has IPv6 on
  CONF_HAS_V6=0
  if printf '%s' "$ADDRS" | grep -q ':'; then CONF_HAS_V6=1; fi
  if [ "$HAS_IP6" = 1 ] && [ "$CONF_HAS_V6" = 1 ]; then PROTON_V6=1; else PROTON_V6=0; fi

  {
    echo "# ProtonVPN WireGuard config - generated by proton.sh (do not edit by hand)"
    echo "[Interface]"
    echo "PrivateKey = $PK"
    old_ifs=$IFS; IFS=','
    for a in $ADDRS; do
      a=$(printf '%s' "$a" | tr -d ' ')
      [ -n "$a" ] && echo "Address = $a"
    done
    IFS=$old_ifs
    echo "MTU = $MTU_VAL"
    echo "Table = off"
    echo "PostUp = $PROTON_UP_HELPER"
    echo "PreDown = $PROTON_DOWN_HELPER"
    echo "# DNS intentionally not set here to avoid overwriting host resolv.conf."
    echo "# (ProtonVPN's internal DNS 10.2.0.1 is only reachable inside the tunnel;"
    echo "#  VPN clients do their own DNS, the VPS host keeps its own resolver.)"
    echo ""
    echo "[Peer]"
    echo "PublicKey = $PUBKEY"
    echo "AllowedIPs = $ALLOWED"
    echo "Endpoint = $PROTON_ENDPOINT"
    echo "PersistentKeepalive = $KEEPALIVE_VAL"
  } > "$PROTON_CONF"
  chmod 600 "$PROTON_CONF"
  bigecho "Wrote $PROTON_CONF (Table=off, PostUp helper, MTU $MTU_VAL, PersistentKeepalive $KEEPALIVE_VAL, v6=$PROTON_V6)"
  grep -v "PrivateKey" "$PROTON_CONF" || true
}

create_helpers() {
  bigecho "Creating helper scripts $PROTON_UP_HELPER and $PROTON_DOWN_HELPER ..."

  # Header lines (values baked in at generation time), then a literal runtime body.
  {
    echo "#!/bin/bash"
    echo "# Auto-generated by proton.sh - DO NOT EDIT MANUALLY"
    echo "set -e"
    echo "PROTON_IF=$PROTON_IF"
    echo "PROTON_TABLE=$PROTON_TABLE"
    echo "PROTON_V6=$PROTON_V6"
    echo "NET_IFACE_DETECTED=$NET_IFACE"
    echo "L2TP_NET=$L2TP_NET"
    echo "XAUTH_NET=$XAUTH_NET"
    echo "IP6_NET=$IP6_NET"
    echo "GW=$GW"
    echo "ENDPOINT_IP=$ENDPOINT_IP"
    echo "ENDPOINT_HOST=$ENDPOINT_HOST"
    echo "ENDPOINT_PORT=$ENDPOINT_PORT"
    cat <<'EOS'

check_ip() { printf '%s' "$1" | grep -Eq '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'; }

# Re-detect GW if stale (may change after reboot)
if [ -z "$GW" ] || ! check_ip "$GW" 2>/dev/null; then
  GW=$(ip -4 route show default dev "$NET_IFACE_DETECTED" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -n1)
  [ -z "$GW" ] && GW=$(ip -4 route get 1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -n1)
fi

# Resolve endpoint host at runtime if not pinned at generation time
if [ -z "$ENDPOINT_IP" ] && [ -n "$ENDPOINT_HOST" ]; then
  ENDPOINT_IP=$(getent ahosts "$ENDPOINT_HOST" 2>/dev/null | awk '{print $1}' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1)
  [ -z "$ENDPOINT_IP" ] && ENDPOINT_IP=$(dig +short A "$ENDPOINT_HOST" 2>/dev/null | head -n1)
fi

# 1) Endpoint bypass via main table (avoid routing loop)
if [ -n "$ENDPOINT_IP" ] && check_ip "$ENDPOINT_IP" && [ -n "$GW" ] && check_ip "$GW"; then
  ip route replace "$ENDPOINT_IP/32" via "$GW" dev "$NET_IFACE_DETECTED" 2>/dev/null || ip route add "$ENDPOINT_IP/32" via "$GW" dev "$NET_IFACE_DETECTED" 2>/dev/null || true
fi

# 2) Policy routing table for VPN clients only (keeps SSH/host on main)
ip route replace default dev "$PROTON_IF" table "$PROTON_TABLE" 2>/dev/null || ip route add default dev "$PROTON_IF" table "$PROTON_TABLE" 2>/dev/null || true
if [ "$PROTON_V6" = 1 ]; then
  ip -6 route replace default dev "$PROTON_IF" table "$PROTON_TABLE" 2>/dev/null || ip -6 route add default dev "$PROTON_IF" table "$PROTON_TABLE" 2>/dev/null || true
fi

# 3) Rules: only FROM VPN subnets -> PROTON (SSH stays on main) - priority 100/101 < main (32766) !
for net in "$L2TP_NET" "$XAUTH_NET"; do
  [ -z "$net" ] && continue
  ip rule del from "$net" table "$PROTON_TABLE" 2>/dev/null || true
  ip rule add from "$net" table "$PROTON_TABLE" priority 100 2>/dev/null || ip rule add from "$net" lookup "$PROTON_TABLE" 2>/dev/null || true
done
if [ "$PROTON_V6" = 1 ] && [ -n "$IP6_NET" ]; then
  ip -6 rule del from "$IP6_NET" table "$PROTON_TABLE" 2>/dev/null || true
  ip -6 rule add from "$IP6_NET" table "$PROTON_TABLE" priority 101 2>/dev/null || ip -6 rule add from "$IP6_NET" lookup "$PROTON_TABLE" priority 101 2>/dev/null || true
fi

# 4) Sysctl for proton interface (performance & no rp_filter drop)
sysctl -w "net.ipv4.conf.$PROTON_IF.rp_filter=0" >/dev/null 2>&1 || true
sysctl -w "net.ipv4.conf.$PROTON_IF.send_redirects=0" >/dev/null 2>&1 || true
sysctl -w "net.ipv4.conf.all.rp_filter=0" >/dev/null 2>&1 || true

# 5) iptables NAT via proton (MASQUERADE) - idempotent
if command -v iptables >/dev/null 2>&1; then
  for net in "$L2TP_NET" "$XAUTH_NET"; do
    [ -z "$net" ] && continue
    if ! iptables -t nat -C POSTROUTING -s "$net" -o "$PROTON_IF" -j MASQUERADE 2>/dev/null; then
      iptables -t nat -I POSTROUTING 1 -s "$net" -o "$PROTON_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$net" -o "$PROTON_IF" -j MASQUERADE 2>/dev/null || true
    fi
  done
  # MSS clamp (both directions) - avoids PMTU blackhole
  if ! iptables -t mangle -C FORWARD -o "$PROTON_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
    iptables -t mangle -A FORWARD -o "$PROTON_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  fi
  if ! iptables -t mangle -C FORWARD -i "$PROTON_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
    iptables -t mangle -A FORWARD -i "$PROTON_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  fi
  # FORWARD accept rules (insert near top, before any final DROP)
  for net in "$L2TP_NET" "$XAUTH_NET"; do
    [ -z "$net" ] && continue
    if ! iptables -C FORWARD -s "$net" -o "$PROTON_IF" -j ACCEPT 2>/dev/null; then
      iptables -I FORWARD 1 -s "$net" -o "$PROTON_IF" -j ACCEPT 2>/dev/null || true
    fi
    if ! iptables -C FORWARD -i "$PROTON_IF" -d "$net" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
      iptables -I FORWARD 2 -i "$PROTON_IF" -d "$net" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    fi
  done
  # L2TP uses ppp+ kernel interfaces
  if ! iptables -C FORWARD -i ppp+ -o "$PROTON_IF" -j ACCEPT 2>/dev/null; then
    iptables -I FORWARD 3 -i ppp+ -o "$PROTON_IF" -j ACCEPT 2>/dev/null || true
  fi
  if ! iptables -C FORWARD -i "$PROTON_IF" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    iptables -I FORWARD 4 -i "$PROTON_IF" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi
fi

# nftables fallback (EL10) - best effort, non-fatal
if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q "hwdsl2"; then
  for net in "$L2TP_NET" "$XAUTH_NET"; do
    [ -z "$net" ] && continue
    nft add rule inet nat postrouting ip saddr "$net" oifname "$PROTON_IF" masquerade 2>/dev/null || true
  done
fi

# IPv6 NAT if the profile has IPv6
if [ "$PROTON_V6" = 1 ] && command -v ip6tables >/dev/null 2>&1 && [ -n "$IP6_NET" ]; then
  if ! ip6tables -t nat -C POSTROUTING -s "$IP6_NET" -o "$PROTON_IF" -j MASQUERADE 2>/dev/null; then
    ip6tables -t nat -I POSTROUTING 1 -s "$IP6_NET" -o "$PROTON_IF" -j MASQUERADE 2>/dev/null || true
  fi
fi

echo "proton-up: routing via $PROTON_IF (table $PROTON_TABLE) for $L2TP_NET, $XAUTH_NET (SSH bypassed via $NET_IFACE_DETECTED)"
EOS
  } > "$PROTON_UP_HELPER"
  chmod +x "$PROTON_UP_HELPER"

  {
    echo "#!/bin/bash"
    echo "# Auto-generated by proton.sh - DO NOT EDIT MANUALLY"
    echo "set -e"
    echo "PROTON_IF=$PROTON_IF"
    echo "PROTON_TABLE=$PROTON_TABLE"
    echo "PROTON_V6=$PROTON_V6"
    echo "L2TP_NET=$L2TP_NET"
    echo "XAUTH_NET=$XAUTH_NET"
    echo "IP6_NET=$IP6_NET"
    echo "ENDPOINT_IP=$ENDPOINT_IP"
    echo "NET_IFACE_DETECTED=$NET_IFACE"
    cat <<'EOS'

# remove policy rules
for net in "$L2TP_NET" "$XAUTH_NET"; do
  [ -z "$net" ] && continue
  ip rule del from "$net" table "$PROTON_TABLE" 2>/dev/null || true
done
if [ "$PROTON_V6" = 1 ]; then
  ip -6 rule del from "$IP6_NET" table "$PROTON_TABLE" 2>/dev/null || true
fi
ip route flush table "$PROTON_TABLE" 2>/dev/null || true

# remove iptables proton rules (only rules matching this interface)
if command -v iptables >/dev/null 2>&1; then
  for net in "$L2TP_NET" "$XAUTH_NET"; do
    [ -z "$net" ] && continue
    iptables -t nat -D POSTROUTING -s "$net" -o "$PROTON_IF" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -s "$net" -o "$PROTON_IF" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$PROTON_IF" -d "$net" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  done
  iptables -t mangle -D FORWARD -o "$PROTON_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  iptables -t mangle -D FORWARD -i "$PROTON_IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  iptables -D FORWARD -i ppp+ -o "$PROTON_IF" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$PROTON_IF" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
fi
if [ "$PROTON_V6" = 1 ] && command -v ip6tables >/dev/null 2>&1; then
  ip6tables -t nat -D POSTROUTING -s "$IP6_NET" -o "$PROTON_IF" -j MASQUERADE 2>/dev/null || true
fi
echo "proton-down: cleaned table $PROTON_TABLE and iptables for $PROTON_IF"
EOS
  } > "$PROTON_DOWN_HELPER"
  chmod +x "$PROTON_DOWN_HELPER"
  bigecho "Helpers created."
}

enable_systemd() {
  if command -v systemctl >/dev/null 2>&1; then
    bigecho "Enabling wg-quick@${PROTON_IF} via systemd..."
    systemctl enable "wg-quick@${PROTON_IF}" 2>/dev/null || true
    # drop-in: start after network is ready (avoid SSH race) and restart on failure
    mkdir -p "/etc/systemd/system/wg-quick@${PROTON_IF}.service.d"
    cat > "/etc/systemd/system/wg-quick@${PROTON_IF}.service.d/override.conf" <<EOF
[Unit]
After=network-online.target nss-lookup.target
Wants=network-online.target
[Service]
Restart=on-failure
RestartSec=5
EOF
    systemctl daemon-reload
    bigecho "Starting ProtonVPN interface $PROTON_IF ..."
    # Pre-add endpoint bypass before wg-quick brings up (avoids loop during handshake)
    if [ -n "$ENDPOINT_IP" ] && [ -n "$GW" ]; then
      ip route replace "$ENDPOINT_IP/32" via "$GW" dev "$NET_IFACE" 2>/dev/null || ip route add "$ENDPOINT_IP/32" via "$GW" dev "$NET_IFACE" 2>/dev/null || true
    fi
    wg-quick down "$PROTON_IF" 2>/dev/null || true
    wg-quick up "$PROTON_IF" 2>&1 | tee /tmp/proton-wg-quick.log
    wg_quick_rc=${PIPESTATUS[0]}
    if [ "$wg_quick_rc" -ne 0 ]; then
      cat /tmp/proton-wg-quick.log >&2
      exiterr "wg-quick up $PROTON_IF failed (rc=$wg_quick_rc). Check $PROTON_CONF and 'wg show' / 'journalctl -u wg-quick@${PROTON_IF}'"
    fi
    bigecho "ProtonVPN $PROTON_IF up."
    # verify PostUp ran
    sleep 1
    "$PROTON_UP_HELPER" || true
  elif [ "$os_type" = "alpine" ]; then
    bigecho "Enabling ProtonVPN via OpenRC..."
    rc-update add "wg-quick.${PROTON_IF}" default 2>/dev/null || {
      ln -sf /etc/init.d/wg-quick "/etc/init.d/wg-quick.${PROTON_IF}" 2>/dev/null || true
      rc-update add "wg-quick.${PROTON_IF}" default 2>/dev/null || true
    }
    wg-quick up "$PROTON_IF" 2>/dev/null || wg-quick up "$PROTON_IF"
  else
    bigecho "No systemd/OpenRC found - bringing up ProtonVPN manually..."
    wg-quick up "$PROTON_IF" || exiterr "wg-quick up failed"
  fi
}

persist_iptables() {
  # Rules are re-applied by proton-up helper on every boot (PostUp). Just leave a marker
  # in persistent rule files so it is obvious where they come from.
  if [ -f /etc/iptables.rules ] && ! grep -q "proton" /etc/iptables.rules 2>/dev/null; then
    echo "# ProtonVPN routing rules managed by $PROTON_UP_HELPER (table $PROTON_TABLE)" >> /etc/iptables.rules || true
  fi
  if [ -f /etc/sysconfig/iptables ] && ! grep -q "proton" /etc/sysconfig/iptables 2>/dev/null; then
    echo "# ProtonVPN routing rules managed by $PROTON_UP_HELPER" >> /etc/sysconfig/iptables || true
  fi
}

do_status() {
  echo "=== ProtonVPN (WireGuard) Status ==="
  echo "Interface: $PROTON_IF  Table: $PROTON_TABLE  Conf: $PROTON_CONF"
  echo "NET_IFACE: ${NET_IFACE:-unknown}  L2TP_NET: ${L2TP_NET:-?}  XAUTH_NET: ${XAUTH_NET:-?}"
  echo
  echo "--- wg show ---"
  wg show "$PROTON_IF" 2>&1 || echo "wg $PROTON_IF not up"
  echo
  echo "--- ip link ---"
  ip link show dev "$PROTON_IF" 2>&1 || echo "no link $PROTON_IF"
  echo
  echo "--- ip rule (should show from L2TP/XAUTH -> table $PROTON_TABLE) ---"
  ip rule show 2>&1 | cat
  ip -6 rule show 2>&1 | cat || true
  echo
  echo "--- ip route table $PROTON_TABLE ---"
  ip route show table "$PROTON_TABLE" 2>&1 | cat
  ip -6 route show table "$PROTON_TABLE" 2>&1 | cat || true
  echo
  echo "--- endpoint bypass ---"
  if [ -n "$ENDPOINT_IP" ]; then
    ip route get "$ENDPOINT_IP" 2>&1 | cat
  else
    ep_line=$(grep -i "^Endpoint" "$PROTON_CONF" 2>/dev/null | cut -d= -f2- | tr -d ' \r' | head -n1)
    if [ -n "$ep_line" ]; then
      ep_host=$(printf '%s' "$ep_line" | sed 's/:[0-9]*$//')
      case "$ep_host" in
        *.*) ip route get "$(getent ahosts "$ep_host" 2>/dev/null | awk '{print $1}' | head -n1)" 2>&1 | cat || true ;;
      esac
    fi
  fi
  echo
  echo "--- iptables NAT (proton) ---"
  iptables -t nat -S 2>&1 | grep -i "proton\|192\.168\.4[23]" | head -n 20
  echo
  echo "--- iptables mangle MSS clamp ---"
  iptables -t mangle -S 2>&1 | grep -i "TCPMSS.*proton\|clamp" | head -n 20
  echo
  echo "--- egress check via ProtonVPN ---"
  if ip route show table "$PROTON_TABLE" | grep -q "dev $PROTON_IF"; then
    echo "Proton table has default via $PROTON_IF - routing active."
    if ip link show dev "$PROTON_IF" >/dev/null 2>&1 && wg show "$PROTON_IF" 2>/dev/null | grep -q "latest handshake"; then
      echo "Handshake: OK"
      if command -v curl >/dev/null 2>&1; then
        echo "Trying curl --interface $PROTON_IF https://ifconfig.co (8s timeout) ..."
        timeout 8 curl --interface "$PROTON_IF" -s https://ifconfig.co 2>&1 | head -n 3 || echo "curl via $PROTON_IF failed - check 'wg show' handshake / ProtonVPN account"
      fi
    else
      echo "No handshake yet - check: wg show $PROTON_IF"
    fi
  else
    echo "Proton table missing default route!"
  fi
  echo
  echo "--- SSH safety check ---"
  echo "Main default route (should be via $NET_IFACE, NOT $PROTON_IF):"
  ip -4 route show default 2>&1 | cat
  if ip -4 route show default | grep -q "dev $PROTON_IF"; then
    echo "WARNING: main default via $PROTON_IF -> SSH may be at risk! Table=off should prevent this."
  else
    echo "OK: main default stays via $NET_IFACE (SSH safe)"
  fi
}

do_uninstall() {
  bigecho "Disabling ProtonVPN routing (VPN will revert to direct)..."
  if ip link show dev "$PROTON_IF" >/dev/null 2>&1; then
    wg-quick down "$PROTON_IF" 2>/dev/null || ip link del "$PROTON_IF" 2>/dev/null || true
  fi
  if [ -x "$PROTON_DOWN_HELPER" ]; then
    "$PROTON_DOWN_HELPER" 2>/dev/null || true
  else
    for net in "$L2TP_NET" "$XAUTH_NET"; do
      [ -z "$net" ] && continue
      ip rule del from "$net" table "$PROTON_TABLE" 2>/dev/null || true
    done
    ip route flush table "$PROTON_TABLE" 2>/dev/null || true
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable "wg-quick@${PROTON_IF}" 2>/dev/null || true
    rm -f "/etc/systemd/system/wg-quick@${PROTON_IF}.service.d/override.conf"
    systemctl daemon-reload 2>/dev/null || true
  fi
  bigecho "ProtonVPN disabled. Config kept at $PROTON_CONF (remove manually if desired)."
  bigecho "VPN clients now go direct via $NET_IFACE again. No reboot needed."
}

do_install() {
  check_vpn_installed
  detect_iface
  detect_subnets
  install_wireguard_pkgs
  ensure_proton_conf
  resolve_endpoint_ip
  create_helpers
  enable_systemd
  persist_iptables
  echo
  bigecho "ProtonVPN enabled successfully!"
  echo "  Interface: $PROTON_IF (table $PROTON_TABLE)  Endpoint: ${PROTON_ENDPOINT:-unknown}"
  echo "  VPN clients ($L2TP_NET, $XAUTH_NET) -> ProtonVPN -> Internet"
  echo "  Server/host & SSH -> direct via $NET_IFACE (safe)"
  echo "  IPv6 via Proton: $PROTON_V6 (IPv6 traffic stays direct when profile is IPv4-only)"
  echo
  if ip rule show 2>/dev/null | grep -q "table 51820"; then
    echo "NOTE: WARP (table 51820) rules are currently active for the same client subnets."
    echo "      WARP and ProtonVPN are alternatives - only one can route client traffic at a time."
    echo "      To use Proton:  sudo bash extras/warp.sh uninstall   (then re-run proton.sh)"
    echo "      To switch back: sudo bash proton.sh uninstall && sudo bash extras/warp.sh"
    echo
  fi
  do_status
  echo
  echo "To test: connect IKEv2 client, then visit https://ifconfig.co - should show a ProtonVPN IP, not server IP"
  echo "Server SSH remains via $NET_IFACE gateway ${GW:-unknown}"
  echo "Manage: sudo bash $0 status | uninstall | restart"
}

# main
check_root
check_os
# detect early for status/uninstall without full install
detect_iface >/dev/null 2>&1 || NET_IFACE="eth0"
detect_subnets >/dev/null 2>&1 || true
if [ -s "$PROTON_CONF" ]; then
  PROTON_ENDPOINT=$(grep -i "^Endpoint" "$PROTON_CONF" | cut -d= -f2- | tr -d ' \r' | head -n1)
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
    bigecho "Restarting ProtonVPN..."
    if ip link show dev "$PROTON_IF" >/dev/null 2>&1; then
      wg-quick down "$PROTON_IF" 2>/dev/null || true
      sleep 1
      wg-quick up "$PROTON_IF" 2>/dev/null || true
      "$PROTON_UP_HELPER" 2>/dev/null || true
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
