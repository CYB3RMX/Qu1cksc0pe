#!/bin/bash
# Build a Debian .deb package for Qu1cksc0pe.
# Usage: bash build_deb.sh
# Output: .deb_build/qu1cksc0pe_<version>_all.deb
set -euo pipefail

# ── Metadata ───────────────────────────────────────────────────────────────────
PACKAGE="qu1cksc0pe"
VERSION="2026.03.03"
ARCH="all"
MAINTAINER="CYB3RMX <https://github.com/CYB3RMX>"
HOMEPAGE="https://github.com/CYB3RMX/Qu1cksc0pe"
DESCRIPTION_SHORT="All-in-One malware analysis tool"
DESCRIPTION_LONG="\
 Qu1cksc0pe analyzes Windows/Linux/macOS/Android executables,
 documents, archives, PCAP files, e-mail files, and scripts.
 It provides static and dynamic analysis with MITRE ATT&CK
 mappings, API extraction, and embedded executable detection."

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/.deb_build"
PKG_ROOT="${BUILD_DIR}/${PACKAGE}_${VERSION}_${ARCH}"
DEBIAN_DIR="${PKG_ROOT}/DEBIAN"
INSTALL_DIR="${PKG_ROOT}/opt/Qu1cksc0pe"
BIN_DIR="${PKG_ROOT}/usr/bin"
DOC_DIR="${PKG_ROOT}/usr/share/doc/${PACKAGE}"
MAN_DIR="${PKG_ROOT}/usr/share/man/man1"
ETC_DIR="${PKG_ROOT}/etc"
OUT_DEB="${BUILD_DIR}/${PACKAGE}_${VERSION}_${ARCH}.deb"

# ── Dependency check ───────────────────────────────────────────────────────────
for dep in dpkg-deb gzip; do
    if ! command -v "$dep" &>/dev/null; then
        echo "Error: '$dep' not found. Install with: apt-get install dpkg-dev" >&2
        exit 1
    fi
done

# ── Clean build dir ────────────────────────────────────────────────────────────
echo "[*] Cleaning previous build..."
rm -rf "${PKG_ROOT}"
mkdir -p "${DEBIAN_DIR}" "${INSTALL_DIR}" "${BIN_DIR}" "${DOC_DIR}" \
         "${MAN_DIR}" "${ETC_DIR}"

# ── Copy project files (explicit exclusions) ───────────────────────────────────
echo "[*] Copying project files..."
EXCLUDES=(
    ".git" ".github" ".claude" ".deb_build"
    "__pycache__" "*.pyc" "*.pyo"
    ".venv" "venv" "sc0pe"
    "webui_uploads" "sc0pe_reports"
    "setup.ps1" "Dockerfile" ".dockerignore" ".gitignore"
    "build_deb.sh"
)

# Build rsync-style exclude args for cp by listing what we DO want
_copy_filtered() {
    local src="$1" dst="$2"
    mkdir -p "$dst"
    for item in "$src"/.[!.]* "$src"/*; do
        [ -e "$item" ] || continue
        local base
        base="$(basename "$item")"
        local skip=0
        for excl in "${EXCLUDES[@]}"; do
            # glob match against basename
            # shellcheck disable=SC2254
            case "$base" in
                $excl) skip=1; break ;;
            esac
        done
        [ "$skip" -eq 1 ] && continue
        cp -a "$item" "$dst/"
    done
}

_copy_filtered "${SCRIPT_DIR}" "${INSTALL_DIR}"

# Remove installer.sh — replaced by deb packaging
rm -f "${INSTALL_DIR}/Modules/installer.sh"

# Strip compiled bytecode and cache dirs
find "${INSTALL_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${INSTALL_DIR}" -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null || true

# ── Docs ───────────────────────────────────────────────────────────────────────
echo "[*] Installing docs..."
cp "${SCRIPT_DIR}/LICENSE" "${DOC_DIR}/copyright"

# Minimal compressed changelog (required by Debian policy)
printf '%s (%s) unstable; urgency=low\n\n  * See README.md for full changelog.\n\n -- %s  %s\n' \
    "${PACKAGE}" "${VERSION}" "${MAINTAINER}" "$(date -R)" \
    | gzip -9 > "${DOC_DIR}/changelog.gz"

# ── Man page ───────────────────────────────────────────────────────────────────
echo "[*] Generating man page..."
cat > "${BUILD_DIR}/qu1cksc0pe.1" <<'MANEOF'
.TH QU1CKSC0PE 1 "2026-03-02" "2026.03.02" "Qu1cksc0pe Manual"
.SH NAME
qu1cksc0pe \- All-in-One malware analysis tool
.SH SYNOPSIS
.B qu1cksc0pe
[\fIOPTIONS\fR]
.SH DESCRIPTION
Qu1cksc0pe analyzes many file types including Windows/Linux/macOS executables,
Android packages, documents, archives, PCAP files, and scripts.
It provides static and dynamic analysis with MITRE ATT\&CK mappings.
.SH OPTIONS
.TP
.B \-\-file \fIFILE\fR
Target file to analyze.
.TP
.B \-\-folder \fIDIR\fR
Target folder to scan.
.TP
.B \-\-analyze
Auto-detect file type and analyze.
.TP
.B \-\-docs
Analyze document files.
.TP
.B \-\-archive
Analyze archive files.
.TP
.B \-\-watch
Dynamic behavioral analysis.
.TP
.B \-\-domain
Extract URLs and IP addresses.
.TP
.B \-\-hashscan
Scan file hash against malware database.
.TP
.B \-\-packer
Detect packers and protectors.
.TP
.B \-\-resource
Analyze PE resources.
.TP
.B \-\-sigcheck
Scan embedded file signatures.
.TP
.B \-\-lang
Detect programming language.
.TP
.B \-\-vtFile
Scan with VirusTotal API (requires \-\-key_init).
.TP
.B \-\-key_init
Save VirusTotal API key.
.TP
.B \-\-report
Export analysis results as JSON.
.TP
.B \-\-ai
Run AI-powered smart analysis on report.
.TP
.B \-\-db_update
Update malware hash database.
.TP
.B \-\-ui
Launch web UI.
.SH FILES
.I /etc/qu1cksc0pe.conf
.RS
Path configuration (set during installation).
.RE
.I /opt/Qu1cksc0pe/Systems/
.RS
YARA rules, detection databases, and configuration files.
.RE
.SH HOMEPAGE
https://github.com/CYB3RMX/Qu1cksc0pe
.SH LICENSE
GNU General Public License v3.0
MANEOF
gzip -9 < "${BUILD_DIR}/qu1cksc0pe.1" > "${MAN_DIR}/qu1cksc0pe.1.gz"
rm "${BUILD_DIR}/qu1cksc0pe.1"

# ── Entrypoint wrapper ─────────────────────────────────────────────────────────
echo "[*] Writing entrypoint..."
cat > "${BIN_DIR}/qu1cksc0pe" <<'ENTRY'
#!/bin/bash
exec /opt/Qu1cksc0pe/venv/bin/python3 /opt/Qu1cksc0pe/qu1cksc0pe.py "$@"
ENTRY
chmod 755 "${BIN_DIR}/qu1cksc0pe"

# ── File permissions ───────────────────────────────────────────────────────────
echo "[*] Setting permissions..."
find "${INSTALL_DIR}" -type d  -exec chmod 755 {} \;
find "${INSTALL_DIR}" -type f  -exec chmod 644 {} \;
find "${INSTALL_DIR}" -name "*.sh" -exec chmod 755 {} \;
chmod 755 "${INSTALL_DIR}/qu1cksc0pe.py"

# ── DEBIAN/control ─────────────────────────────────────────────────────────────
echo "[*] Writing DEBIAN/control..."
# Calculate installed size (kB)
INSTALLED_SIZE=$(du -sk "${INSTALL_DIR}" | cut -f1)

cat > "${DEBIAN_DIR}/control" <<EOF
Package: ${PACKAGE}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Installed-Size: ${INSTALLED_SIZE}
Depends: python3 (>= 3.8), python3-pip, python3-venv, binutils, libmagic1,
 default-jre-headless, unzip, curl | wget
Recommends: p7zip-full, adb, strace, ltrace, dos2unix, unrar | unar
Section: utils
Priority: optional
Homepage: ${HOMEPAGE}
Description: ${DESCRIPTION_SHORT}
${DESCRIPTION_LONG}
EOF

# ── DEBIAN/postinst ────────────────────────────────────────────────────────────
cat > "${DEBIAN_DIR}/postinst" <<'EOF'
#!/bin/bash
set -euo pipefail

INSTALL_DIR="/opt/Qu1cksc0pe"
VENV_DIR="${INSTALL_DIR}/venv"
CONF_FILE="/etc/qu1cksc0pe.conf"
JADX_VERSION="1.5.3"
JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
JADX_DIR="${INSTALL_DIR}/jadx"
LIBSCANNER_CONF="${INSTALL_DIR}/Systems/Android/libScanner.conf"

# ── Downloader helper ──────────────────────────────────────────────────────
_download() {
    local url="$1" dest="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$dest"
    else
        echo "qu1cksc0pe: neither curl nor wget found — skipping download of $url" >&2
        return 1
    fi
}

# ── JADX installation ──────────────────────────────────────────────────────
_install_jadx() {
    # Already on PATH → record and return
    if command -v jadx &>/dev/null; then
        echo "qu1cksc0pe: jadx already on PATH: $(command -v jadx)"
        JADX_BIN="$(command -v jadx)"
        return 0
    fi

    # Already installed in JADX_DIR
    local launcher="${JADX_DIR}/bin/jadx"
    if [[ -f "${launcher}" ]]; then
        echo "qu1cksc0pe: jadx already present at ${launcher}"
        chmod -R a+rX "${JADX_DIR}" 2>/dev/null || true
        JADX_BIN="${launcher}"
        return 0
    fi

    echo "qu1cksc0pe: downloading JADX v${JADX_VERSION}..."
    local tmp_zip tmp_dir
    tmp_zip="$(mktemp -t jadx-XXXXXX.zip)"
    tmp_dir="$(mktemp -d -t jadx-XXXXXX)"
    if ! _download "${JADX_URL}" "${tmp_zip}"; then
        rm -f "${tmp_zip}"; rm -rf "${tmp_dir}"
        echo "qu1cksc0pe: WARNING — JADX download failed. APK decompilation will be unavailable." >&2
        return 1
    fi

    unzip -q "${tmp_zip}" -d "${tmp_dir}"
    mkdir -p "${JADX_DIR}"
    cp -a "${tmp_dir}/." "${JADX_DIR}/"
    rm -f "${tmp_zip}"; rm -rf "${tmp_dir}"

    chmod +x "${launcher}" 2>/dev/null || true
    dos2unix -q "${launcher}" 2>/dev/null || true

    if [[ -f "${launcher}" ]]; then
        chmod -R a+rX "${JADX_DIR}"
        echo "qu1cksc0pe: JADX installed at ${launcher}"
        JADX_BIN="${launcher}"
        return 0
    else
        echo "qu1cksc0pe: WARNING — JADX launcher not found after installation." >&2
        return 1
    fi
}

# ── Ollama installation ────────────────────────────────────────────────────
_install_ollama() {
    if command -v ollama &>/dev/null; then
        echo "qu1cksc0pe: ollama already installed."
        return 0
    fi

    echo "qu1cksc0pe: installing Ollama..."
    local tmp_script
    tmp_script="$(mktemp -t ollama-install-XXXXXX.sh)"
    if ! _download "https://ollama.com/install.sh" "${tmp_script}"; then
        rm -f "${tmp_script}"
        echo "qu1cksc0pe: WARNING — Ollama download failed. Install manually: curl -fsSL https://ollama.com/install.sh | sh" >&2
        return 1
    fi

    if bash "${tmp_script}"; then
        rm -f "${tmp_script}"
        if command -v ollama &>/dev/null; then
            echo "qu1cksc0pe: Ollama installed successfully."

            # Pull model from config if present
            local conf="${INSTALL_DIR}/Systems/Multiple/multiple.conf"
            if [[ -f "${conf}" ]]; then
                local model
                model="$(awk -F'=' '
                    BEGIN{in_s=0}
                    /^\[Ollama\]/{in_s=1;next}
                    in_s && /^\[/{in_s=0}
                    in_s && $1~/^[[:space:]]*model[[:space:]]*$/{
                        v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/,"",v); print v; exit
                    }' "${conf}" || true)"
                if [[ -n "${model}" ]]; then
                    echo "qu1cksc0pe: pulling Ollama model '${model}' (this may take a while)..."
                    systemctl start ollama 2>/dev/null || true
                    sleep 2
                    ollama pull "${model}" || \
                        echo "qu1cksc0pe: WARNING — model pull failed. Run manually: ollama pull ${model}" >&2
                fi
            fi
            return 0
        fi
    fi

    rm -f "${tmp_script}"
    echo "qu1cksc0pe: WARNING — Ollama installation failed. Install manually: curl -fsSL https://ollama.com/install.sh | sh" >&2
    return 1
}

# ── Main ───────────────────────────────────────────────────────────────────
case "$1" in
    configure)
        echo "qu1cksc0pe: creating Python virtual environment..."
        python3 -m venv "${VENV_DIR}"

        echo "qu1cksc0pe: installing Python dependencies (this may take a while)..."
        "${VENV_DIR}/bin/pip" install --upgrade pip --quiet
        "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet

        echo "qu1cksc0pe: installing pyOneNote..."
        "${VENV_DIR}/bin/pip" install -q --force-reinstall \
            https://github.com/DissectMalware/pyOneNote/archive/master.zip || \
            echo "qu1cksc0pe: WARNING — pyOneNote installation failed." >&2

        echo "qu1cksc0pe: writing configuration..."
        printf '[Qu1cksc0pe_PATH]\nsc0pe = %s\n' "${INSTALL_DIR}" > "${CONF_FILE}"
        chmod 644 "${CONF_FILE}"

        echo "qu1cksc0pe: creating runtime directories..."
        mkdir -p "${INSTALL_DIR}/webui_uploads" "${INSTALL_DIR}/sc0pe_reports"
        chmod 1777 "${INSTALL_DIR}/webui_uploads" "${INSTALL_DIR}/sc0pe_reports"

        # JADX
        JADX_BIN=""
        _install_jadx || true
        if [[ -n "${JADX_BIN}" && -f "${LIBSCANNER_CONF}" ]]; then
            sed -i "s|^decompiler = .*|decompiler = ${JADX_BIN}|g" "${LIBSCANNER_CONF}"
            echo "qu1cksc0pe: libScanner.conf updated with JADX path: ${JADX_BIN}"
        fi

        # Ollama
        _install_ollama || true

        echo ""
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║           Qu1cksc0pe — Installation Complete                     ║"
        echo "╠══════════════════════════════════════════════════════════════════╣"
        echo "║                                                                  ║"
        echo "║  NEXT STEPS (required for full functionality):                   ║"
        echo "║                                                                  ║"
        echo "║  1) Sign in to Ollama (AI features):                             ║"
        echo "║       ollama signin                                               ║"
        echo "║                                                                  ║"
        echo "║  2) Save your VirusTotal API key (VT scanning):                  ║"
        echo "║       qu1cksc0pe --key_init                                       ║"
        echo "║                                                                  ║"
        echo "║  Run  qu1cksc0pe --help  to see all options.                     ║"
        echo "║                                                                  ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo ""
        ;;
esac

exit 0
EOF
chmod 755 "${DEBIAN_DIR}/postinst"

# ── DEBIAN/prerm ───────────────────────────────────────────────────────────────
cat > "${DEBIAN_DIR}/prerm" <<'EOF'
#!/bin/bash
set -euo pipefail

case "$1" in
    remove|purge|upgrade)
        echo "qu1cksc0pe: removing virtual environment..."
        rm -rf /opt/Qu1cksc0pe/venv
        ;;
esac

exit 0
EOF
chmod 755 "${DEBIAN_DIR}/prerm"

# ── DEBIAN/postrm ──────────────────────────────────────────────────────────────
cat > "${DEBIAN_DIR}/postrm" <<'EOF'
#!/bin/bash
set -euo pipefail

case "$1" in
    purge)
        echo "qu1cksc0pe: purging installation..."
        rm -f  /etc/qu1cksc0pe.conf
        rm -rf /opt/Qu1cksc0pe
        ;;
    remove)
        rm -f /etc/qu1cksc0pe.conf
        ;;
esac

exit 0
EOF
chmod 755 "${DEBIAN_DIR}/postrm"

# ── Build .deb ─────────────────────────────────────────────────────────────────
echo "[*] Building .deb package..."
dpkg-deb --build --root-owner-group "${PKG_ROOT}" "${OUT_DEB}"

echo ""
echo "[+] Package ready: ${OUT_DEB}"
echo ""
echo "    Install:   sudo dpkg -i ${OUT_DEB}"
echo "    Remove:    sudo apt remove ${PACKAGE}"
echo "    Purge:     sudo apt purge ${PACKAGE}"
