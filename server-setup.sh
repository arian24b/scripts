#!/usr/bin/env bash
# server-setup.sh
# Install path aliases: sstup, server-setup
# Idempotent + capability-checked server bootstrapper (Debian/Ubuntu/RPi OS)
# Author: ArianOmrani

set -euo pipefail

# =========================================================
# Version
# =========================================================
VERSION="1.0.0"

# =========================================================
# Install targets
# =========================================================
SELF_NAMES=("server-setup" "sstup")
SELF_DIR="/usr/local/sbin"
LOCK_FILE="/var/lock/server-setup.lock"

# Default update URL
DEFAULT_SELF_UPDATE_URL="https://github.com/arian24b/scripts/raw/refs/heads/main/server-setup.sh"

# =========================================================
# APT DEFAULTS (baseline - always installed)
# Print with: server-setup --print-apt
# =========================================================
APT_PACKAGES_DEFAULT=(
  ca-certificates curl wget git gnupg lsb-release jq
  build-essential unzip zip zstd
  tmux nano vim screen
  htop iotop nload net-tools dnsutils
  software-properties-common
  openssh-server ufw
  fail2ban tuned dphys-swapfile iperf3
)

# =========================================================
# Defaults (behavior)
# =========================================================
LOCATION="auto"                  # auto|iran|global
DO_UPDATE=0                      # -U / --update
PROXY=""                         # -p / --proxy  socks5://... | http(s)://...
INSTALL_SET=""                   # -i / --install  (non-apt installers only)
APT_ADD=""                       # --apt-add pkg1,pkg2
APT_REMOVE=""                    # --apt-remove pkg1,pkg2
PRINT_APT=0                      # --print-apt
DRY_RUN=0                        # -n / --dry-run

# Logging / debug
LOG_PATH=""                      # -l / --log
DEBUG=0                          # -d / --debug

# Cleanup
DO_CLEANUP=1                     # -c / --cleanup
CLEANUP_LEVEL="basic"            # -C / --cleanup-level basic|full

# System defaults (idempotent)
ENABLE_IR_OPTIMIZATIONS=1
ENABLE_FAIL2BAN=1
ENABLE_TUNED=1
TUNED_PROFILE="network-latency"
ENABLE_RCLOCAL=1

# swap/placeholder/journal
SWAP_MB="0"                      # -s / --swap-size (MB)
TMP_PATH="/home/.placeholder"    # -t / --tmp-path
TMP_SIZE="0"                     # -T / --tmp-size
JOURNAL_SIZE="10M"               # --journal-size
JOURNAL_TIME="7d"                # --journal-time

# Pi overclock
OVERCLOCK_PROFILE=""             # -o / --overclock safe|performance

# SSH harden + keys (optional)
SSH_HARDEN=0                     # --ssh-harden
SSH_PORT="3232"                  # --ssh-port
SSH_ALLOW_USERS=""               # --ssh-allow-users "user1,user2"
SSH_PUBKEY_URL="https://github.com/arian24b.keys"   # --ssh-pubkey-url https://github.com/arian24b.keys

# Self install/update/completion
SELF_INSTALL=1                   # --self-install
SELF_UNINSTALL=0                 # --self-uninstall
SELF_UPDATE_URL=""               # --self-update [url]
PRINT_INSTALL_PATH=0             # --print-install-path
INSTALL_COMPLETION=1             # --install-completion

# =========================================================
# Output helpers
# =========================================================
log()  { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err()  { echo -e "\033[1;31m[x]\033[0m $*" >&2; }
die()  { err "$*"; exit 1; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# =========================================================
# Dry-run wrapper
# =========================================================
run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $*"
    return 0
  fi
  eval "$@"
}

# =========================================================
# Logging / debug
# =========================================================
enable_logging() {
  if [[ -n "$LOG_PATH" ]]; then
    mkdir -p "$(dirname "$LOG_PATH")"
    touch "$LOG_PATH"
    # Redirect stdout/stderr through tee, preserving exit codes with pipefail
    exec > >(tee -a "$LOG_PATH") 2>&1
    log "Logging enabled: $LOG_PATH"
  fi
}

enable_debug() {
  [[ "$DEBUG" -eq 1 ]] && set -x
}

# =========================================================
# Lock file (avoid concurrent runs)
# =========================================================
acquire_lock() {
  need_root
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    die "Another server-setup is already running (lock: $LOCK_FILE)"
  fi
  # Ensure lock released on exit
  trap 'release_lock' EXIT
}

release_lock() {
  # fd 9 will be closed automatically; this is just explicit
  flock -u 9 2>/dev/null || true
}

# =========================================================
# Capabilities checks
# =========================================================
has_systemd() { [[ -d /run/systemd/system ]] && cmd_exists systemctl; }
has_resolved() { has_systemd && systemctl list-unit-files 2>/dev/null | grep -q '^systemd-resolved\.service'; }
has_journalctl() { cmd_exists journalctl; }
has_dpkg() { cmd_exists dpkg; }
has_apt() { cmd_exists apt-get; }

is_raspberry_pi() {
  [[ -f /proc/device-tree/model ]] && tr -d '\0' </proc/device-tree/model | grep -qi "raspberry pi"
}

rpi_boot_config_path() {
  [[ -f /boot/firmware/config.txt ]] && { echo "/boot/firmware/config.txt"; return; }
  [[ -f /boot/config.txt ]] && { echo "/boot/config.txt"; return; }
  # best guess
  echo "/boot/firmware/config.txt"
}

# =========================================================
# Proxy wrappers
# =========================================================
CURL="curl -fsSL"
WGET="wget -q"

apply_proxy_env() {
  [[ -n "$PROXY" ]] || return 0
  export http_proxy="$PROXY" https_proxy="$PROXY" HTTP_PROXY="$PROXY" HTTPS_PROXY="$PROXY"
}

wrap_net_tools() {
  apply_proxy_env
  if [[ -n "$PROXY" ]]; then
    if [[ "$PROXY" =~ ^socks5:// ]]; then
      CURL="curl -fsSL --proxy ${PROXY/socks5:\/\//socks5h:\/\/}"
      WGET="wget -q" # rely on env; socks support varies
    else
      CURL="curl -fsSL --proxy $PROXY"
      WGET="wget -q -e use_proxy=yes -e http_proxy=$PROXY -e https_proxy=$PROXY"
    fi
  fi
}

write_apt_proxy_conf() {
  [[ -n "$PROXY" ]] || return 0
  if [[ "$PROXY" =~ ^https?:// ]]; then
    run "cat > /etc/apt/apt.conf.d/99proxy <<'EOF'
Acquire::http::Proxy \"${PROXY}\";
Acquire::https::Proxy \"${PROXY}\";
EOF"
    log "APT proxy configured (/etc/apt/apt.conf.d/99proxy)"
  else
    warn "APT proxy not configured (PROXY is not http(s)://). APT may not support socks directly."
  fi
}

# =========================================================
# Country detection: ifconfig.io first, then chabokan
# =========================================================
get_country_code() {
  local cc=""
  cc="$($CURL --max-time 4 ifconfig.io/country_code 2>/dev/null || true)"
  cc="$(echo -n "$cc" | tr -d ' \r\n\t')"
  [[ -n "$cc" ]] && { echo "$cc"; return 0; }

  local ip json
  ip="$($CURL --max-time 4 ifconfig.io/ip 2>/dev/null || true)"
  ip="$(echo -n "$ip" | tr -d ' \r\n\t')"
  [[ -z "$ip" ]] && { echo ""; return 0; }

  json="$($CURL --max-time 4 "https://chabokan.net/ip/?address=${ip}" 2>/dev/null || true)"
  [[ -z "$json" ]] && { echo ""; return 0; }

  if cmd_exists jq; then
    cc="$(echo "$json" | jq -r '.country_code // .countryCode // .country // empty' 2>/dev/null || true)"
    cc="$(echo -n "$cc" | tr -d ' \r\n\t')"
    echo "$cc"
  else
    cc="$(echo "$json" | grep -Eo '"country_code"\s*:\s*"[^"]+"' | head -n1 | cut -d'"' -f4 || true)"
    cc="$(echo -n "$cc" | tr -d ' \r\n\t')"
    echo "$cc"
  fi
}

is_iran() { [[ "$(get_country_code || true)" == "IR" ]]; }

# =========================================================
# OS detection
# =========================================================
source /etc/os-release || true
OS_ID="${ID:-unknown}"
OS_LIKE="${ID_LIKE:-}"
is_ubuntu() { [[ "$OS_ID" == "ubuntu" ]] || echo "$OS_LIKE" | grep -qi "ubuntu"; }
is_debian() { [[ "$OS_ID" == "debian" ]] || echo "$OS_LIKE" | grep -qi "debian"; }

# =========================================================
# DNS + mirrors (idempotent)
# =========================================================
set_shecan_dns_systemd_resolved() {
  has_resolved || { warn "systemd-resolved not available; skipping Shecan DNS."; return 0; }

  run "mkdir -p /etc/systemd/resolved.conf.d"
  run "cat > /etc/systemd/resolved.conf.d/99-shecan.conf <<'EOF'
[Resolve]
DNS=178.22.122.100 185.51.200.2
FallbackDNS=1.1.1.1 8.8.8.8
EOF"

  run "systemctl enable systemd-resolved >/dev/null 2>&1 || true"
  run "systemctl restart systemd-resolved >/dev/null 2>&1 || true"

  # Link resolv.conf to resolved stub if possible
  if [[ -e /run/systemd/resolve/stub-resolv.conf ]]; then
    run "ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || true"
  elif [[ -e /run/systemd/resolve/resolv.conf ]]; then
    run "ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf || true"
  fi

  log "DNS set to Shecan (systemd-resolved)."
}

set_arvan_mirrors_ubuntu() {
  local arvan="http://mirror.arvancloud.ir/ubuntu"
  if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    run "sed -i -E \"s#URIs:\\s*https?://[^ ]+#URIs: ${arvan}#g\" /etc/apt/sources.list.d/ubuntu.sources || true"
  fi
  if [[ -f /etc/apt/sources.list ]]; then
    run "sed -i -E \
      -e \"s#https?://(archive|security)\\.ubuntu\\.com/ubuntu#${arvan}#g\" \
      -e \"s#https?://[a-z]{2}\\.archive\\.ubuntu\\.com/ubuntu#${arvan}#g\" \
      /etc/apt/sources.list || true"
  fi
  run "find /etc/apt/sources.list.d -maxdepth 1 -type f -name \"*.list\" -print0 2>/dev/null \
    | xargs -0 -I{} sed -i -E \
      -e \"s#https?://(archive|security)\\.ubuntu\\.com/ubuntu#${arvan}#g\" \
      -e \"s#https?://[a-z]{2}\\.archive\\.ubuntu\\.com/ubuntu#${arvan}#g\" {} || true"
  log "Ubuntu mirrors updated to ArvanCloud."
}

set_arvan_mirrors_debian_deb822() {
  local arvan_deb="http://mirror.arvancloud.ir/debian"
  local arvan_sec="http://mirror.arvancloud.ir/debian-security"
  local f="/etc/apt/sources.list.d/debian.sources"
  [[ -f "$f" ]] || return 0

  run "sed -i -E \
    -e \"s#URIs:\\s*https?://deb\\.debian\\.org/debian#URIs: ${arvan_deb}#g\" \
    -e \"s#URIs:\\s*https?://security\\.debian\\.org/debian-security#URIs: ${arvan_sec}#g\" \
    -e \"s#URIs:\\s*https?://deb\\.debian\\.org/#URIs: ${arvan_deb}/#g\" \
    -e \"s#URIs:\\s*https?://security\\.debian\\.org/#URIs: ${arvan_sec}/#g\" \
    \"$f\" || true"
  log "Debian mirrors updated in deb822 ($f)."
}

set_arvan_mirrors_debian() {
  set_arvan_mirrors_debian_deb822 || true
  local arvan_deb="http://mirror.arvancloud.ir/debian"
  local arvan_sec="http://mirror.arvancloud.ir/debian-security"

  if [[ -f /etc/apt/sources.list ]]; then
    run "sed -i -E \
      -e \"s#https?://deb\\.debian\\.org/debian#${arvan_deb}#g\" \
      -e \"s#https?://security\\.debian\\.org/debian-security#${arvan_sec}#g\" \
      -e \"s#https?://ftp\\.[^/]+/debian#${arvan_deb}#g\" \
      /etc/apt/sources.list || true"
  fi

  run "find /etc/apt/sources.list.d -maxdepth 1 -type f -name \"*.list\" -print0 2>/dev/null \
    | xargs -0 -I{} sed -i -E \
      -e \"s#https?://deb\\.debian\\.org/debian#${arvan_deb}#g\" \
      -e \"s#https?://security\\.debian\\.org/debian-security#${arvan_sec}#g\" \
      -e \"s#https?://ftp\\.[^/]+/debian#${arvan_deb}#g\" {} || true"

  log "Debian mirrors updated to ArvanCloud."
}

set_rpios_raspberrypi_repo_iut() {
  local iut_repo="http://repo.iut.ac.ir/repo/archive.raspberrypi.org/debian"

  if [[ -f /etc/apt/sources.list.d/raspi.sources ]]; then
    run "sed -i -E \"s#URIs:\\s*https?://archive\\.raspberrypi\\.org/debian#URIs: ${iut_repo}#g\" \
      /etc/apt/sources.list.d/raspi.sources || true"
    log "RPi repo updated in raspi.sources (IUT)."
    return 0
  fi

  if [[ -f /etc/apt/sources.list.d/raspi.list ]]; then
    run "sed -i -E \"s#https?://archive\\.raspberrypi\\.org/debian#${iut_repo}#g\" \
      /etc/apt/sources.list.d/raspi.list || true"
    log "RPi repo updated in raspi.list (IUT)."
  fi
}

apply_location_optimizations() {
  [[ "$ENABLE_IR_OPTIMIZATIONS" -eq 1 ]] || { log "IR optimizations disabled."; return 0; }

  local do_ir=0
  case "$LOCATION" in
    iran) do_ir=1 ;;
    global) do_ir=0 ;;
    auto)
      if is_iran; then do_ir=1; else do_ir=0; fi
      ;;
    *) die "--location must be auto|iran|global" ;;
  esac

  if [[ "$do_ir" -eq 1 ]]; then
    log "Location => IR mode (Arvan mirrors + Shecan DNS + RPi repo IUT)."
    set_shecan_dns_systemd_resolved
    if is_raspberry_pi; then set_rpios_raspberrypi_repo_iut || true; fi
    if is_ubuntu; then set_arvan_mirrors_ubuntu
    elif is_debian; then set_arvan_mirrors_debian
    else warn "Unknown distro ($OS_ID). Skipping mirror changes."
    fi
  else
    log "Location => Global mode (no mirror/DNS changes)."
  fi
}

# =========================================================
# APT list modifiers
# =========================================================
csv_to_array() {
  local csv="${1:-}"
  csv="$(echo -n "$csv" | tr -d ' \t\r\n')"
  [[ -z "$csv" ]] && return 0
  IFS=',' read -r -a _out <<<"$csv"
  printf '%s\n' "${_out[@]}"
}

build_apt_list() {
  local pkgs=("${APT_PACKAGES_DEFAULT[@]}")
  local add remove p

  if [[ -n "$APT_ADD" ]]; then
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      # add if not present
      if ! printf '%s\n' "${pkgs[@]}" | grep -qxF "$p"; then
        pkgs+=("$p")
      fi
    done < <(csv_to_array "$APT_ADD")
  fi

  if [[ -n "$APT_REMOVE" ]]; then
    while IFS= read -r remove; do
      [[ -z "$remove" ]] && continue
      pkgs=($(printf '%s\n' "${pkgs[@]}" | grep -vxF "$remove" || true))
    done < <(csv_to_array "$APT_REMOVE")
  fi

  printf '%s\n' "${pkgs[@]}"
}

print_apt() {
  build_apt_list
}

# =========================================================
# APT baseline install
# =========================================================
apt_install_baseline() {
  has_apt || die "apt-get not found; this tool supports Debian/Ubuntu family."

  log "APT update..."
  run "apt-get update -y || apt-get update -y --fix-missing"

  log "Installing baseline APT packages..."
  mapfile -t pkgs < <(build_apt_list)
  # shellcheck disable=SC2145
  run "apt-get install -y --no-install-recommends ${pkgs[*]}"

  if [[ "$DO_UPDATE" -eq 1 ]]; then
    log "Upgrading system packages (--update)..."
    run "apt-get upgrade -y || true"
    run "apt-get dist-upgrade -y || true"
  fi

  run "apt-get autoremove -y || true"
  run "apt-get clean || true"
}

# =========================================================
# Default system setup (idempotent)
# =========================================================
setup_journal_defaults() {
  has_journalctl || { warn "journalctl not available; skipping journal vacuum."; return 0; }
  [[ -n "$JOURNAL_SIZE" ]] && run "journalctl --vacuum-size=\"$JOURNAL_SIZE\" || true"
  [[ -n "$JOURNAL_TIME" ]] && run "journalctl --vacuum-time=\"$JOURNAL_TIME\" || true"
  log "journalctl vacuum applied (size=$JOURNAL_SIZE, time=$JOURNAL_TIME)"
}

setup_swap_dphys() {
  [[ "$SWAP_MB" != "0" ]] || return 0
  [[ -f /etc/dphys-swapfile ]] || { warn "dphys-swapfile config missing; skipping swap."; return 0; }

  # Idempotent set of CONF_SWAPSIZE
  if grep -q '^CONF_SWAPSIZE=' /etc/dphys-swapfile; then
    run "sed -i -E \"s/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=${SWAP_MB}/\" /etc/dphys-swapfile"
  else
    run "echo \"CONF_SWAPSIZE=${SWAP_MB}\" >> /etc/dphys-swapfile"
  fi

  if has_systemd; then
    run "systemctl enable dphys-swapfile >/dev/null 2>&1 || true"
    run "systemctl restart dphys-swapfile >/dev/null 2>&1 || true"
  else
    run "dphys-swapfile setup || true"
    run "dphys-swapfile swapon || true"
  fi
  log "Swap configured via dphys-swapfile: ${SWAP_MB} MB"
}

setup_tmp_placeholder() {
  [[ "$TMP_SIZE" != "0" ]] || return 0
  run "rm -f \"$TMP_PATH\" || true"
  run "fallocate -l \"$TMP_SIZE\" \"$TMP_PATH\""
  log "Placeholder file created: $TMP_PATH ($TMP_SIZE)"
}

setup_fail2ban_default() {
  [[ "$ENABLE_FAIL2BAN" -eq 1 ]] || return 0
  has_systemd || { warn "systemd not present; skipping fail2ban enable."; return 0; }
  run "systemctl enable fail2ban >/dev/null 2>&1 || true"
  run "systemctl restart fail2ban >/dev/null 2>&1 || true"
  log "fail2ban enabled"
}

setup_tuned_default() {
  [[ "$ENABLE_TUNED" -eq 1 ]] || return 0
  has_systemd || { warn "systemd not present; skipping tuned enable."; return 0; }
  cmd_exists tuned-adm || { warn "tuned-adm not found; skipping tuned profile."; return 0; }
  run "systemctl enable tuned >/dev/null 2>&1 || true"
  run "systemctl restart tuned >/dev/null 2>&1 || true"
  run "tuned-adm profile \"$TUNED_PROFILE\" || true"
  log "tuned enabled (profile=$TUNED_PROFILE)"
}

setup_rc_local_default() {
  [[ "$ENABLE_RCLOCAL" -eq 1 ]] || return 0
  has_systemd || { warn "systemd not present; skipping rc-local service."; return 0; }

  # Create /etc/rc.local if missing (idempotent)
  if [[ ! -f /etc/rc.local ]]; then
    run "cat > /etc/rc.local <<'EOF'
#!/usr/bin/env bash
exit 0
EOF"
    run "chmod +x /etc/rc.local"
  fi

  # Create rc-local.service if missing (idempotent)
  if [[ ! -f /etc/systemd/system/rc-local.service ]]; then
    run "cat > /etc/systemd/system/rc-local.service <<'EOF'
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
RemainAfterExit=yes
GuessMainPID=no

[Install]
WantedBy=multi-user.target
EOF"
  fi

  run "systemctl daemon-reload || true"
  run "systemctl enable rc-local.service >/dev/null 2>&1 || true"
  run "systemctl restart rc-local.service >/dev/null 2>&1 || true"
  log "rc.local enabled"
}

install_ssh_pubkey_to_root() {
  [[ -n "$SSH_PUBKEY_URL" ]] || return 0
  run "mkdir -p /root/.ssh"
  run "chmod 700 /root/.ssh"
  run "touch /root/.ssh/authorized_keys"
  run "chmod 600 /root/.ssh/authorized_keys"

  local keys
  keys="$($CURL "$SSH_PUBKEY_URL" || true)"
  [[ -n "$keys" ]] || { warn "Could not fetch SSH keys from $SSH_PUBKEY_URL"; return 0; }

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if ! grep -qxF "$line" /root/.ssh/authorized_keys; then
      run "echo \"$line\" >> /root/.ssh/authorized_keys"
    fi
  done <<<"$keys"

  log "Root authorized_keys updated from $SSH_PUBKEY_URL"
}

setup_ssh_hardening() {
  [[ "$SSH_HARDEN" -eq 1 ]] || return 0
  local f="/etc/ssh/sshd_config"
  [[ -f "$f" ]] || { warn "sshd_config not found; skipping SSH harden."; return 0; }

  [[ -f "${f}.bak" ]] || run "cp -a \"$f\" \"${f}.bak\""

  # idempotent set
  run "sed -i -E \
    -e 's/^\\s*#?\\s*PasswordAuthentication\\s+.*/PasswordAuthentication no/' \
    -e 's/^\\s*#?\\s*PermitRootLogin\\s+.*/PermitRootLogin no/' \
    -e 's/^\\s*#?\\s*PubkeyAuthentication\\s+.*/PubkeyAuthentication yes/' \
    \"$f\" || true"

  if [[ -n "$SSH_PORT" ]]; then
    if grep -qE '^\s*Port\s+' "$f"; then
      run "sed -i -E \"s/^\\s*Port\\s+.*/Port ${SSH_PORT}/\" \"$f\""
    else
      run "echo \"Port ${SSH_PORT}\" >> \"$f\""
    fi
  fi

  if [[ -n "$SSH_ALLOW_USERS" ]]; then
    local allow_line="AllowUsers ${SSH_ALLOW_USERS//,/ }"
    if grep -qE '^\s*AllowUsers\s+' "$f"; then
      run "sed -i -E \"s/^\\s*AllowUsers\\s+.*/${allow_line}/\" \"$f\""
    else
      run "echo \"$allow_line\" >> \"$f\""
    fi
  fi

  if has_systemd; then
    run "systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true"
  fi
  log "SSH hardening applied."
}

apply_pi_overclock() {
  [[ -n "$OVERCLOCK_PROFILE" ]] || return 0
  is_raspberry_pi || { warn "Not a Raspberry Pi; skipping overclock."; return 0; }

  local cfg; cfg="$(rpi_boot_config_path)"
  run "mkdir -p \"$(dirname "$cfg")\""
  run "touch \"$cfg\""

  local model; model="$(tr -d '\0' </proc/device-tree/model | tr -d '\r\n' || true)"
  log "Overclock: model='$model' profile='$OVERCLOCK_PROFILE' file='$cfg'"

  # Remove prior block (idempotent)
  run "sed -i '/^# --- ARIAN OVERCLOCK BEGIN ---$/,/^# --- ARIAN OVERCLOCK END ---$/d' \"$cfg\" || true"

  # Append new block
  local block=""
  block+=$'\n# --- ARIAN OVERCLOCK BEGIN ---\n'
  block+="# Profile: ${OVERCLOCK_PROFILE}"$'\n'
  block+="# Note: force_turbo intentionally not set."$'\n'
  if echo "$model" | grep -qi "Raspberry Pi 4"; then
    if [[ "$OVERCLOCK_PROFILE" == "performance" ]]; then
      block+="arm_freq=2000"$'\n'
      block+="over_voltage=6"$'\n'
      block+="gpu_freq=600"$'\n'
    else
      block+="arm_freq=1800"$'\n'
      block+="over_voltage=2"$'\n'
      block+="gpu_freq=550"$'\n'
    fi
  elif echo "$model" | grep -qi "Zero 2"; then
    if [[ "$OVERCLOCK_PROFILE" == "performance" ]]; then
      block+="arm_freq=1300"$'\n'
      block+="over_voltage=6"$'\n'
      block+="core_freq=525"$'\n'
    else
      block+="arm_freq=1200"$'\n'
      block+="over_voltage=2"$'\n'
      block+="core_freq=525"$'\n'
    fi
  else
    block+="arm_freq=1600"$'\n'
    block+="over_voltage=2"$'\n'
  fi
  block+="# --- ARIAN OVERCLOCK END ---"$'\n'

  run "printf '%s' \"$block\" >> \"$cfg\""
  warn "Overclock written. Reboot required."
}

# =========================================================
# Non-APT installers (only via --install)
# =========================================================
has_install() {
  local item="$1"
  [[ ",${INSTALL_SET}," == *",${item},"* ]]
}

install_uv() {
  if cmd_exists uv; then
    [[ "$DO_UPDATE" -eq 1 ]] && run "uv self update || true"
    log "uv already installed"
    return 0
  fi
  log "Installing uv..."
  run "$CURL https://astral.sh/uv/install.sh | sh"
  # uv installs in ~/.local/bin for root
  export PATH="$PATH:/root/.local/bin"
}

install_docker() {
  if cmd_exists docker; then
    [[ "$DO_UPDATE" -eq 1 ]] && { log "Updating Docker via installer..."; run "$CURL https://get.docker.com | sh || true"; }
    log "docker already installed"
    return 0
  fi
  log "Installing docker..."
  run "$CURL https://get.docker.com | sh"
  if has_systemd; then
    run "systemctl enable docker >/dev/null 2>&1 || true"
    run "systemctl restart docker >/dev/null 2>&1 || true"
  fi
}

install_ollama() {
  if cmd_exists ollama; then
    [[ "$DO_UPDATE" -eq 1 ]] && { log "Updating Ollama via installer..."; run "$CURL https://ollama.com/install.sh | sh || true"; }
    log "ollama already installed"
    return 0
  fi
  log "Installing ollama..."
  run "$CURL https://ollama.com/install.sh | sh"
}

# =========================================================
# Cleanup
# =========================================================
cleanup_basic() {
  log "Cleanup (basic)..."
  run "apt-get autoremove -y || true"
  run "apt-get clean || true"
  # safer tmp cleanup: only old files
  run "find /tmp -type f -mtime +2 -delete 2>/dev/null || true"
  run "find /var/tmp -type f -mtime +2 -delete 2>/dev/null || true"
  log "Cleanup basic done."
}

cleanup_full() {
  log "Cleanup (full)..."
  run "apt-get autoremove -y || true"
  run "apt-get clean || true"
  run "apt-get autoclean || true"
  setup_journal_defaults || true
  run "find /tmp -type f -mtime +1 -delete 2>/dev/null || true"
  run "find /var/tmp -type f -mtime +1 -delete 2>/dev/null || true"
  run "rm -f /var/cache/apt/archives/*.deb 2>/dev/null || true"
  log "Cleanup full done."
}

run_cleanup_if_requested() {
  [[ "$DO_CLEANUP" -eq 1 ]] || return 0
  case "$CLEANUP_LEVEL" in
    basic) cleanup_basic ;;
    full)  cleanup_full ;;
    *) warn "Unknown cleanup level '$CLEANUP_LEVEL' => basic"; cleanup_basic ;;
  esac
}

# =========================================================
# Self install / update / uninstall
# =========================================================
script_realpath() {
  if cmd_exists readlink; then
    readlink -f "$0" 2>/dev/null || echo "$0"
  else
    echo "$0"
  fi
}

self_install() {
  need_root
  local src; src="$(script_realpath)"
  [[ -f "$src" ]] || die "Cannot self-install: source not found ($src)"

  run "mkdir -p \"$SELF_DIR\""
  run "install -m 0755 \"$src\" \"$SELF_DIR/server-setup\""
  run "ln -sf \"$SELF_DIR/server-setup\" \"$SELF_DIR/sstup\""
  log "Installed: $SELF_DIR/server-setup and symlink $SELF_DIR/sstup"
}

self_uninstall() {
  need_root
  run "rm -f \"$SELF_DIR/server-setup\" \"$SELF_DIR/sstup\""
  log "Uninstalled server-setup and sstup from $SELF_DIR"
}

self_update() {
  need_root
  local url="${SELF_UPDATE_URL:-$DEFAULT_SELF_UPDATE_URL}"
  [[ -n "$url" ]] || die "--self-update requires a URL (or set DEFAULT_SELF_UPDATE_URL in script)."

  local tmp="/tmp/server-setup.new.$$"
  run "$CURL \"$url\" -o \"$tmp\""
  [[ "$DRY_RUN" -eq 1 ]] && { log "dry-run: downloaded update to $tmp"; return 0; }

  [[ -s "$tmp" ]] || die "Downloaded update is empty."
  head -n1 "$tmp" | grep -qE '^#!/usr/bin/env bash|^#!/bin/bash' || die "Update doesn't look like a bash script."

  chmod 0755 "$tmp"
  run "mkdir -p \"$SELF_DIR\""
  run "mv -f \"$tmp\" \"$SELF_DIR/server-setup\""
  run "ln -sf \"$SELF_DIR/server-setup\" \"$SELF_DIR/sstup\""
  log "Updated installed script at $SELF_DIR/server-setup"
}

# =========================================================
# Completion
# =========================================================
completion_script_bash() {
  cat <<'EOF'
# Bash completion for server-setup / sstup
_server_setup_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  local opts="
    -h --help
    -V --version
    -n --dry-run
    -d --debug
    -l --log
    -L --location
    -i --install
    -p --proxy
    -U --update
    -c --cleanup
    -C --cleanup-level
    -s --swap-size
    -t --tmp-path
    -T --tmp-size
    -j --journal-size
    -J --journal-time
    -o --overclock
    --ssh-harden
    --ssh-port
    --ssh-allow-users
    --ssh-pubkey-url
    --apt-add
    --apt-remove
    --print-apt
    --self-install
    --self-update
    --self-uninstall
    --print-install-path
    --install-completion
  "

  case "$prev" in
    -L|--location)
      COMPREPLY=( $(compgen -W "auto iran global" -- "$cur") )
      return 0
      ;;
    -i|--install)
      COMPREPLY=( $(compgen -W "docker ollama uv" -- "$cur") )
      return 0
      ;;
    -C|--cleanup-level)
      COMPREPLY=( $(compgen -W "basic full" -- "$cur") )
      return 0
      ;;
    -o|--overclock)
      COMPREPLY=( $(compgen -W "safe performance" -- "$cur") )
      return 0
      ;;
    -l|--log|-p|--proxy|-s|--swap-size|-t|--tmp-path|-T|--tmp-size|-j|--journal-size|-J|--journal-time|--ssh-port|--ssh-allow-users|--ssh-pubkey-url|--apt-add|--apt-remove|--self-update)
      COMPREPLY=()
      return 0
      ;;
  esac

  COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
}
complete -F _server_setup_complete server-setup sstup
EOF
}

install_completion() {
  # Install completion for current shell (bash/zsh supported)
  local shell="${SHELL:-}"
  if [[ -n "${BASH_VERSION:-}" ]] || echo "$shell" | grep -qi bash; then
    local dir="/etc/bash_completion.d"
    run "mkdir -p \"$dir\""
    run "cat > \"$dir/server-setup\" <<'EOF'
$(completion_script_bash)
EOF"
    log "Bash completion installed to /etc/bash_completion.d/server-setup"
    log "Reload shell or run: source /etc/bash_completion"
    return 0
  fi

  # zsh: install as bashcompinit wrapper
  if echo "$shell" | grep -qi zsh; then
    local dir="/usr/local/share/zsh/site-functions"
    run "mkdir -p \"$dir\""
    run "cat > \"$dir/_server-setup\" <<'EOF'
#compdef server-setup sstup
autoload -U +X bashcompinit && bashcompinit
source /etc/bash_completion.d/server-setup 2>/dev/null || true
EOF"
    # ensure bash completion exists too
    install_completion_bash_only || true
    log "Zsh completion installed to $dir/_server-setup"
    return 0
  fi

  warn "Shell not recognized for completion install. Supported: bash, zsh."
}

install_completion_bash_only() {
  local dir="/etc/bash_completion.d"
  run "mkdir -p \"$dir\""
  run "cat > \"$dir/server-setup\" <<'EOF'
$(completion_script_bash)
EOF"
}

# =========================================================
# Help / version
# =========================================================
usage() {
  cat <<EOF
server-setup ($VERSION)

Usage:
  server-setup [options]

Core:
  -h, --help                         Display the concise help for this command
  -V, --version                      Display the server-setup version
  -n, --dry-run                      Show actions without making changes
  -d, --debug                        Enable bash debug (set -x)
  -l, --log PATH                     Tee output to log file (e.g. /var/log/setup.log)
  -L, --location MODE                auto|iran|global
  -p, --proxy URL                    socks5://IP:PORT or http(s)://IP:PORT
  -U, --update                       Upgrade apt packages + update selected installers where possible

APT baseline:
      --print-apt                    Print baseline apt packages and exit
      --apt-add LIST                 Add apt packages (comma-separated)
      --apt-remove LIST              Remove apt packages (comma-separated)

System tuning:
  -s, --swap-size MB                 Configure swap with dphys-swapfile (MB)
  -t, --tmp-path PATH                Placeholder path (default: $TMP_PATH)
  -T, --tmp-size SIZE                Placeholder size (e.g. 2G)
  -j, --journal-size SIZE            journalctl vacuum size (default: $JOURNAL_SIZE)
  -J, --journal-time TIME            journalctl vacuum time (default: $JOURNAL_TIME)
  -o, --overclock PROFILE            safe|performance (Raspberry Pi only)
  -c, --cleanup                      Cleanup after run (basic)
  -C, --cleanup-level LEVEL          basic|full

SSH options:
      --ssh-harden                   Disable password auth + root login (idempotent)
      --ssh-port PORT                Change SSH port
      --ssh-allow-users user1,user2  Set AllowUsers
      --ssh-pubkey-url URL           Append pubkeys to /root/.ssh/authorized_keys

Non-APT installers (only via --install):
  -i, --install LIST                 docker,ollama,uv (comma-separated)

Self management:
      --self-install                 Install to $SELF_DIR/server-setup and alias $SELF_DIR/sstup
      --self-update [URL]            Update installed script from URL (or DEFAULT_SELF_UPDATE_URL)
      --self-uninstall               Remove installed commands
      --print-install-path           Print install path and exit
      --install-completion           Install completion for the current shell

Examples:
  sudo server-setup -L auto -l /var/log/setup.log
  sudo server-setup -L iran -i docker,ollama,uv -U -l /var/log/setup.log
  sudo server-setup --self-install
  sudo server-setup --install-completion
EOF
}

show_version() {
  echo "$VERSION"
}

# =========================================================
# Args
# =========================================================
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -V|--version) show_version; exit 0 ;;

      -n|--dry-run) DRY_RUN=1; shift ;;
      -d|--debug) DEBUG=1; shift ;;
      -l|--log) LOG_PATH="${2:-}"; shift 2 ;;
      -L|--location) LOCATION="${2:-}"; shift 2 ;;
      -p|--proxy) PROXY="${2:-}"; shift 2 ;;
      -U|--update) DO_UPDATE=1; shift ;;

      -i|--install) INSTALL_SET="$(echo -n "${2:-}" | tr -d ' \t\r\n')"; shift 2 ;;

      --print-apt) PRINT_APT=1; shift ;;
      --apt-add) APT_ADD="${2:-}"; shift 2 ;;
      --apt-remove) APT_REMOVE="${2:-}"; shift 2 ;;

      -s|--swap-size) SWAP_MB="${2:-}"; shift 2 ;;
      -t|--tmp-path) TMP_PATH="${2:-}"; shift 2 ;;
      -T|--tmp-size) TMP_SIZE="${2:-}"; shift 2 ;;
      -j|--journal-size) JOURNAL_SIZE="${2:-}"; shift 2 ;;
      -J|--journal-time) JOURNAL_TIME="${2:-}"; shift 2 ;;
      -o|--overclock) OVERCLOCK_PROFILE="${2:-}"; shift 2 ;;
      -c|--cleanup) DO_CLEANUP=1; shift ;;
      -C|--cleanup-level) DO_CLEANUP=1; CLEANUP_LEVEL="${2:-basic}"; shift 2 ;;

      --ssh-harden) SSH_HARDEN=1; shift ;;
      --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
      --ssh-allow-users) SSH_ALLOW_USERS="${2:-}"; shift 2 ;;
      --ssh-pubkey-url) SSH_PUBKEY_URL="${2:-}"; shift 2 ;;

      --self-install) SELF_INSTALL=1; shift ;;
      --self-uninstall) SELF_UNINSTALL=1; shift ;;
      --self-update)
        # URL optional
        if [[ -n "${2:-}" && ! "${2:-}" =~ ^- ]]; then
          SELF_UPDATE_URL="${2:-}"
          shift 2
        else
          SELF_UPDATE_URL=""
          shift
        fi
        ;;
      --print-install-path) PRINT_INSTALL_PATH=1; shift ;;
      --install-completion) INSTALL_COMPLETION=1; shift ;;

      *) die "Unknown option: $1 (use --help)" ;;
    esac
  done
}

# =========================================================
# Main
# =========================================================
main() {
  need_root
  # Allow: curl ... | bash - -h
  # If first arg is "-", shift it away (bash stdin marker)
  if [[ "${1:-}" == "-" ]]; then
    shift
  fi
  parse_args "$@"

  if [[ "$PRINT_INSTALL_PATH" -eq 1 ]]; then
    echo "$SELF_DIR/server-setup"
    exit 0
  fi

  # Logging/debug should happen early
  enable_logging
  enable_debug

  # Acquire lock (after logging so messages are captured)
  acquire_lock

  wrap_net_tools
  write_apt_proxy_conf

  # Self-management actions (don’t do full run)
  if [[ "$SELF_INSTALL" -eq 1 ]]; then
    self_install
    exit 0
  fi
  if [[ "$SELF_UNINSTALL" -eq 1 ]]; then
    self_uninstall
    exit 0
  fi
  if [[ "$SELF_UPDATE_REQUESTED" -eq 1 ]]; then
    self_update
    exit 0
  fi
  # If user passed --self-update (with or without URL), update and exit
  # (We detect by presence of arg; simplest: if user used --self-update it sets SELF_UPDATE_URL or leaves it empty but we still want to run)
  # Since we can't perfectly detect without extra flag, we use this: if "$1" had --self-update we would have consumed it; so we add a separate flag:
}

# --- detect explicit --self-update use (fix) ---
SELF_UPDATE_REQUESTED=0
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -V|--version) show_version; exit 0 ;;

      -n|--dry-run) DRY_RUN=1; shift ;;
      -d|--debug) DEBUG=1; shift ;;
      -l|--log) LOG_PATH="${2:-}"; shift 2 ;;
      -L|--location) LOCATION="${2:-}"; shift 2 ;;
      -p|--proxy) PROXY="${2:-}"; shift 2 ;;
      -U|--update) DO_UPDATE=1; shift ;;

      -i|--install) INSTALL_SET="$(echo -n "${2:-}" | tr -d ' \t\r\n')"; shift 2 ;;

      --print-apt) PRINT_APT=1; shift ;;
      --apt-add) APT_ADD="${2:-}"; shift 2 ;;
      --apt-remove) APT_REMOVE="${2:-}"; shift 2 ;;

      -s|--swap-size) SWAP_MB="${2:-}"; shift 2 ;;
      -t|--tmp-path) TMP_PATH="${2:-}"; shift 2 ;;
      -T|--tmp-size) TMP_SIZE="${2:-}"; shift 2 ;;
      -j|--journal-size) JOURNAL_SIZE="${2:-}"; shift 2 ;;
      -J|--journal-time) JOURNAL_TIME="${2:-}"; shift 2 ;;
      -o|--overclock) OVERCLOCK_PROFILE="${2:-}"; shift 2 ;;
      -c|--cleanup) DO_CLEANUP=1; shift ;;
      -C|--cleanup-level) DO_CLEANUP=1; CLEANUP_LEVEL="${2:-basic}"; shift 2 ;;

      --ssh-harden) SSH_HARDEN=1; shift ;;
      --ssh-port) SSH_PORT="${2:-}"; shift 2 ;;
      --ssh-allow-users) SSH_ALLOW_USERS="${2:-}"; shift 2 ;;
      --ssh-pubkey-url) SSH_PUBKEY_URL="${2:-}"; shift 2 ;;

      --self-install) SELF_INSTALL=1; shift ;;
      --self-uninstall) SELF_UNINSTALL=1; shift ;;
      --self-update)
        SELF_UPDATE_REQUESTED=1
        if [[ -n "${2:-}" && ! "${2:-}" =~ ^- ]]; then
          SELF_UPDATE_URL="${2:-}"
          shift 2
        else
          SELF_UPDATE_URL=""
          shift
        fi
        ;;
      --print-install-path) PRINT_INSTALL_PATH=1; shift ;;
      --install-completion) INSTALL_COMPLETION=1; shift ;;

      *) die "Unknown option: $1 (use --help)" ;;
    esac
  done
}

main() {
  need_root
  # Allow: curl ... | bash - -h
  # If first arg is "-", shift it away (bash stdin marker)
  if [[ "${1:-}" == "-" ]]; then
    shift
  fi
  parse_args "$@"

  if [[ "$PRINT_APT" -eq 1 ]]; then
    print_apt
    exit 0
  fi

  if [[ "$PRINT_INSTALL_PATH" -eq 1 ]]; then
    echo "$SELF_DIR/server-setup"
    exit 0
  fi

  enable_logging
  enable_debug
  acquire_lock
  wrap_net_tools
  write_apt_proxy_conf

  if [[ "$INSTALL_COMPLETION" -eq 1 ]]; then
    install_completion
    exit 0
  fi

  if [[ "$SELF_INSTALL" -eq 1 ]]; then
    self_install
    exit 0
  fi

  if [[ "$SELF_UNINSTALL" -eq 1 ]]; then
    self_uninstall
    exit 0
  fi

  if [[ "$SELF_UPDATE_REQUESTED" -eq 1 ]]; then
    self_update
    exit 0
  fi

  # Main run
  apply_location_optimizations
  apt_install_baseline

  # Default system setup
  setup_journal_defaults
  setup_swap_dphys
  setup_tmp_placeholder
  setup_fail2ban_default
  setup_tuned_default
  setup_rc_local_default

  install_ssh_pubkey_to_root
  setup_ssh_hardening
  apply_pi_overclock

  # Non-APT installers only if requested
  has_install uv && install_uv
  has_install docker && install_docker
  has_install ollama && install_ollama

  run_cleanup_if_requested

  log "Done."
  warn "If DNS/mirrors/overclock/swap changed, reboot is recommended."
}

main "$@"
