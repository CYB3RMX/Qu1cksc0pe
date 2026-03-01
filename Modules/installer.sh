#!/bin/bash
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
warn="${cyan}[${yellow}!${cyan}]${default}"

INSTALL_DIR="/opt/Qu1cksc0pe"
CONF_FILE="/etc/qu1cksc0pe.conf"
BIN_FILE="/usr/bin/qu1cksc0pe"

# ── Argument validation ────────────────────────────────────────────────────────
if [ "$#" -ne 2 ]; then
    echo -en "$error Usage: installer.sh <sc0pe_path> <username>\n"
    exit 1
fi

sc0pe_path="$1"
normal_user="$2"

# ── Validate sc0pe_path ────────────────────────────────────────────────────────
if [ ! -d "$sc0pe_path" ]; then
    echo -en "$error Source directory not found: $sc0pe_path\n"
    exit 1
fi

for required_file in "qu1cksc0pe.py" "requirements.txt" "Modules" "Systems"; do
    if [ ! -e "$sc0pe_path/$required_file" ]; then
        echo -en "$error Source directory is missing expected file/folder: $required_file\n"
        exit 1
    fi
done

# ── Validate normal_user ───────────────────────────────────────────────────────
if ! id "$normal_user" &>/dev/null; then
    echo -en "$error User '$normal_user' does not exist on this system.\n"
    exit 1
fi

if [ "$normal_user" = "root" ]; then
    echo -en "$error Installing as root user is not allowed. Provide a regular user.\n"
    exit 1
fi

# ── Check root privilege ───────────────────────────────────────────────────────
echo -en "$info Checking user privileges...\n"
if [ "$(id -u)" -ne 0 ]; then
    echo -en "$error You must run this installer with sudo/root privileges.\n"
    exit 1
fi

# ── Dependency checks ──────────────────────────────────────────────────────────
check_deps(){
    local missing=()
    for dep in python3 pip3; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    if [ "${#missing[@]}" -ne 0 ]; then
        echo -en "$error Missing required dependencies: ${missing[*]}\n"
        exit 1
    fi
}

# ── Rollback on failure ────────────────────────────────────────────────────────
_rollback(){
    echo -en "\n$warn Installation failed. Rolling back...\n"
    rm -f  "$BIN_FILE"  2>/dev/null || true
    rm -f  "$CONF_FILE" 2>/dev/null || true
    rm -rf "$INSTALL_DIR" 2>/dev/null || true
    echo -en "$warn Rollback complete.\n"
}

# ── Installer ──────────────────────────────────────────────────────────────────
installer(){
    check_deps

    # Warn if already installed
    if [ -f "$BIN_FILE" ] || [ -d "$INSTALL_DIR" ] || [ -f "$CONF_FILE" ]; then
        echo -en "$warn Qu1cksc0pe appears to be already installed.\n"
        echo -en "$warn Continuing will overwrite the existing installation.\n"
        echo -en "$green>>>>$default Proceed? [y/N] "
        read -r confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo -en "$info Installation aborted.\n"
            exit 0
        fi
        # Clean old install before overwriting
        rm -rf "$INSTALL_DIR" "$BIN_FILE" "$CONF_FILE"
    fi

    trap _rollback ERR

    echo -en "\n$info Starting installation...\n"

    # Install python modules as the normal user to avoid polluting root's env
    echo -en "$info Installing Python dependencies...\n"
    sudo -u "$normal_user" pip3 install --user -r "$sc0pe_path/requirements.txt"

    # Copy project to /opt
    echo -en "$info Copying files to ${green}$INSTALL_DIR${default}...\n"
    cp -r "$sc0pe_path" "$INSTALL_DIR"
    chown -R "$normal_user:$normal_user" "$INSTALL_DIR"

    # Write /etc config
    echo -en "$info Creating configuration file ${green}$CONF_FILE${default}...\n"
    printf '[Qu1cksc0pe_PATH]\nsc0pe = %s\n' "$INSTALL_DIR" > "$CONF_FILE"
    chown "$normal_user:$normal_user" "$CONF_FILE"

    # Write Android libScanner.conf
    {
        printf '[Rule_PATH]\nrulepath = %s/Systems/Android/YaraRules/\n\n' "$INSTALL_DIR"
        printf '[Decompiler]\n'
        if [ -f "/home/$normal_user/sc0pe_Base/jadx/bin/jadx" ]; then
            printf 'decompiler = /home/%s/sc0pe_Base/jadx/bin/jadx\n' "$normal_user"
        elif command -v jadx &>/dev/null; then
            printf 'decompiler = %s\n' "$(command -v jadx)"
        else
            printf 'decompiler = /usr/bin/jadx\n'
        fi
    } > "$INSTALL_DIR/Systems/Android/libScanner.conf"

    # Install entrypoint
    echo -en "$info Installing entrypoint to ${green}$BIN_FILE${default}...\n"
    cp "$sc0pe_path/qu1cksc0pe.py" "$BIN_FILE"
    chmod +x "$BIN_FILE"
    chown "$normal_user:$normal_user" "$BIN_FILE"

    # Normalize line endings
    if command -v dos2unix &>/dev/null; then
        dos2unix "$BIN_FILE" &>/dev/null
    fi

    trap - ERR
    echo -en "$success Installation completed. Run: ${green}qu1cksc0pe --help${default}\n"
}

# ── Uninstaller ────────────────────────────────────────────────────────────────
uninstaller(){
    local found=0

    [ -f "$BIN_FILE" ]   && found=1
    [ -f "$CONF_FILE" ]  && found=1
    [ -d "$INSTALL_DIR" ] && found=1

    if [ "$found" -eq 0 ]; then
        echo -en "$warn Qu1cksc0pe does not appear to be installed. Nothing to do.\n"
        exit 0
    fi

    echo -en "$warn This will remove Qu1cksc0pe from your system.\n"
    echo -en "$green>>>>$default Are you sure? [y/N] "
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -en "$info Uninstallation aborted.\n"
        exit 0
    fi

    echo -en "\n$info Starting uninstallation...\n"

    if [ -f "$BIN_FILE" ]; then
        echo -en "$info Removing ${green}$BIN_FILE${default}...\n"
        rm -f "$BIN_FILE"
    fi

    if [ -f "$CONF_FILE" ]; then
        echo -en "$info Removing ${green}$CONF_FILE${default}...\n"
        rm -f "$CONF_FILE"
    fi

    if [ -d "$INSTALL_DIR" ]; then
        echo -en "$info Removing ${green}$INSTALL_DIR${default}...\n"
        rm -rf "$INSTALL_DIR"
    fi

    echo -en "$success Uninstallation completed.\n"
}

# ── Menu ───────────────────────────────────────────────────────────────────────
menu(){
    echo -en "$info User: ${green}$normal_user${default}\n\n"
    echo -en "${cyan}[${red}1${cyan}]${default} Install Qu1cksc0pe\n"
    echo -en "${cyan}[${red}2${cyan}]${default} Uninstall Qu1cksc0pe\n\n"
    echo -en "$green>>>>$default "
    read -r choice
    case $choice in
        1) installer ;;
        2) uninstaller ;;
        *) echo -en "$error Wrong choice :(\n"
           exit 1 ;;
    esac
}

menu
