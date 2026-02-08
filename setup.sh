#!/usr/bin/env bash
set -euo pipefail

# Colors
cyan='\e[96m'
red='\e[91m'
green='\e[92m'
default='\e[0m'
yellow='\e[93m'

# Legends
info="${cyan}[${yellow}*${cyan}]${default}"
success="${cyan}[${green}+${cyan}]${default}"
error="${cyan}[${red}!${cyan}]${default}"

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

run_with_privilege() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  elif command_exists sudo; then
    sudo "$@"
  else
    log_error "This step requires root privileges, but sudo is not available."
    exit 1
  fi
}

log_info() {
  echo -e "${info} $1"
}

log_success() {
  echo -e "${success} $1"
}

log_error() {
  echo -e "${error} $1"
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
BASE_DIR="${HOME}/sc0pe_Base"
VENV_PYTHON="${SCRIPT_DIR}/sc0pe/bin/python"
PYTHON_BIN="python3"
if [[ -x "${VENV_PYTHON}" ]]; then
  PYTHON_BIN="${VENV_PYTHON}"
fi
JADX_VERSION="1.5.3"
JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
JADX_DIR="${BASE_DIR}/jadx"
LIBSCANNER_CONF="${SCRIPT_DIR}/Systems/Android/libScanner.conf"
JADX_LAUNCHER_PATH=""

# Detect package manager
PKG_MANAGER=""
PKG_INSTALL_CMD=()
PKG_PIP=""
PKG_ADB=""
PKG_MONO=""
PKG_JAVA=""
if command_exists apt-get; then
  PKG_MANAGER="apt"
  PKG_INSTALL_CMD=(apt-get install -y)
  PKG_PIP="python3-pip"
  PKG_ADB="adb"
  PKG_MONO="mono-complete"
  PKG_JAVA="default-jre-headless"
  log_info "APT package manager detected."
elif command_exists pacman; then
  PKG_MANAGER="pacman"
  PKG_INSTALL_CMD=(pacman -S --noconfirm --needed)
  PKG_PIP="python-pip"
  PKG_ADB="android-tools"
  PKG_MONO="mono"
  PKG_JAVA="jre-openjdk-headless"
  log_info "Pacman package manager detected."
else
  log_error "Supported package manager not found (apt-get or pacman)."
  exit 1
fi

install_system_packages() {
  run_with_privilege "${PKG_INSTALL_CMD[@]}" "$@"
}

ensure_cmd_or_install() {
  local cmd_name="$1"
  local pkg_name="$2"
  local note="${3:-}"
  if command_exists "$cmd_name"; then
    log_info "${green}${cmd_name}${default} command is already installed."
    return
  fi
  if [[ -n "$note" ]]; then
    log_info "$note"
  fi
  log_info "Installing ${green}${pkg_name}${default}..."
  install_system_packages "$pkg_name"
  log_success "Installed ${pkg_name}."
}

find_jadx_launcher() {
  local candidate=""
  local subdir=""
  local base_dir=""
  local candidates=(
    "${JADX_DIR}/bin/jadx"
    "${JADX_DIR}/jadx"
  )

  for subdir in "${JADX_DIR}"/*; do
    if [[ -d "${subdir}" ]]; then
      candidates+=("${subdir}/bin/jadx" "${subdir}/jadx")
    fi
  done

  for candidate in "${candidates[@]}"; do
    if [[ -f "${candidate}" ]]; then
      base_dir="$(dirname "${candidate}")"
      # jadx release packaging differs between versions:
      # - older: lib/jadx-cli-<ver>.jar
      # - newer: lib/jadx-<ver>-all.jar
      if [[ -f "${base_dir}/../lib/jadx-cli-${JADX_VERSION}.jar" || -f "${base_dir}/../lib/jadx-${JADX_VERSION}-all.jar" ]]; then
        :
      elif [[ -f "${base_dir}/lib/jadx-cli-${JADX_VERSION}.jar" || -f "${base_dir}/lib/jadx-${JADX_VERSION}-all.jar" ]]; then
        :
      else
        continue
      fi
      chmod +x "${candidate}" 2>/dev/null || true
      dos2unix -q "${candidate}" 2>/dev/null || true
      echo "${candidate}"
      return 0
    fi
  done

  return 1
}

# Ensure pip3
if ! "${PYTHON_BIN}" -m pip --version >/dev/null 2>&1; then
  if [[ "${PYTHON_BIN}" == "python3" ]]; then
    log_info "pip3 is not installed. Installing ${green}${PKG_PIP}${default}..."
    install_system_packages "$PKG_PIP"
  else
    log_error "pip is not available in virtual environment interpreter: ${PYTHON_BIN}"
    exit 1
  fi
fi

# Install python modules
if [[ ! -f requirements.txt ]]; then
  log_error "requirements.txt not found in ${SCRIPT_DIR}."
  exit 1
fi
log_info "Installing python modules from requirements.txt..."
"${PYTHON_BIN}" -m pip install -r requirements.txt
log_success "Python modules installed."

# Setup sc0pe_Base
log_info "Setting up ${green}sc0pe_Base${default} folder in ${green}${BASE_DIR}${default}..."
mkdir -p "$BASE_DIR"
log_success "sc0pe_Base is ready."

# Required system tools
ensure_cmd_or_install adb "$PKG_ADB"
ensure_cmd_or_install strings binutils
ensure_cmd_or_install dos2unix dos2unix
ensure_cmd_or_install unzip unzip

# Ensure downloader is available
if command_exists curl; then
  DOWNLOADER="curl"
elif command_exists wget; then
  DOWNLOADER="wget"
else
  ensure_cmd_or_install wget wget
  DOWNLOADER="wget"
fi

# Setup JADX
if JADX_LAUNCHER_PATH="$(find_jadx_launcher)"; then
  log_info "JADX already exists in ${green}${JADX_DIR}${default}."
  log_info "Detected JADX launcher: ${green}${JADX_LAUNCHER_PATH}${default}"
else
  if [[ -d "$JADX_DIR" ]]; then
    log_info "JADX directory exists but launcher was not found. Re-installing..."
    rm -rf "$JADX_DIR"
  fi

  mkdir -p "$JADX_DIR"
  log_info "Downloading JADX v${JADX_VERSION}..."
  tmp_zip="$(mktemp -t jadx-XXXXXX.zip)"
  tmp_extract="$(mktemp -d -t jadx-XXXXXX)"
  trap 'rm -f "$tmp_zip"; rm -rf "$tmp_extract"' EXIT

  if [[ "$DOWNLOADER" == "curl" ]]; then
    curl -fL "$JADX_URL" -o "$tmp_zip"
  else
    wget "$JADX_URL" -O "$tmp_zip"
  fi

  log_info "Unzipping JADX..."
  unzip -q "$tmp_zip" -d "$tmp_extract"

  cp -a "${tmp_extract}/." "$JADX_DIR/"
  if JADX_LAUNCHER_PATH="$(find_jadx_launcher)"; then
    log_success "JADX installed at ${JADX_DIR}."
    log_info "Detected JADX launcher: ${green}${JADX_LAUNCHER_PATH}${default}"
  else
    log_error "Could not locate JADX launcher after installation."
    exit 1
  fi
fi

# Update libScanner.conf
if [[ -f "$LIBSCANNER_CONF" ]]; then
  log_info "Updating Systems/Android/libScanner.conf..."
  sed -i "s|^decompiler = .*|decompiler = ${JADX_LAUNCHER_PATH}|g" "$LIBSCANNER_CONF"
  log_success "libScanner.conf updated."
else
  log_error "Could not find ${LIBSCANNER_CONF}."
fi

# JADX requires Java runtime
ensure_cmd_or_install java "$PKG_JAVA"

# Check for pyOneNote
if "${PYTHON_BIN}" -c "from pyOneNote.Main import OneDocment" >/dev/null 2>&1; then
  log_info "${green}pyOneNote${default} is already available."
else
  log_info "Installing ${green}pyOneNote${default}..."
  "${PYTHON_BIN}" -m pip install -U --force-reinstall https://github.com/DissectMalware/pyOneNote/archive/master.zip
  log_success "pyOneNote installed."
fi

# Setup mono
if command_exists mono; then
  log_info "${green}mono${default} is already installed."
else
  log_info "Setting up ${green}${PKG_MONO}${default}..."
  install_system_packages "$PKG_MONO"
  log_success "${PKG_MONO} installed."
fi

log_success "All done."
