#!/bin/bash
set -e

echo "============================================================"
echo "  HTTP Proxy - Setup and Run (Linux)"
echo "============================================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

MITMDUMP="mitmproxy/mitmdump"
CERT_FILE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
CONFIG_PATH="../config.json"
CONFIG_SAMPLE="../config.json.sample"

# ============================================================
# STEP 1: Download mitmproxy
# ============================================================
if [ -f "$MITMDUMP" ]; then
    echo "[STEP 1/4] mitmproxy           ... ALREADY EXISTS [SKIP]"
else
    echo "[STEP 1/4] Downloading mitmproxy..."
    echo ""

    for cmd in curl tar; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "  [ERROR] '$cmd' is required but not installed."
            echo "  Install: sudo apt install $cmd / sudo yum install $cmd"
            exit 1
        fi
    done

    echo "  Fetching latest version from GitHub..."
    TAG=$(curl -sL "https://api.github.com/repos/mitmproxy/mitmproxy/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

    if [ -z "$TAG" ]; then
        echo "  [ERROR] Failed to fetch latest version. Check your internet connection."
        exit 1
    fi

    VERSION="${TAG#v}"
    echo "  Latest version: $VERSION"

    FILENAME="mitmproxy-${VERSION}-linux-x86_64.tar.gz"
    DOWNLOAD_URL="https://github.com/mitmproxy/mitmproxy/releases/download/${TAG}/${FILENAME}"

    echo "  Downloading $FILENAME..."
    echo "  URL: $DOWNLOAD_URL"
    echo ""

    if ! curl -L --progress-bar -o "$FILENAME" "$DOWNLOAD_URL"; then
        echo "  [ERROR] Download failed."
        echo "  Download manually: https://mitmproxy.org/downloads/"
        echo "  Extract into mitmproxy/ folder inside this directory."
        rm -f "$FILENAME"
        exit 1
    fi

    echo "  Extracting..."
    rm -rf mitmproxy
    mkdir -p mitmproxy

    if ! tar -xzf "$FILENAME" -C mitmproxy; then
        echo "  [ERROR] Extraction failed."
        exit 1
    fi

    if [ ! -f "$MITMDUMP" ]; then
        echo "  [ERROR] Extraction failed or unexpected archive structure."
        exit 1
    fi

    chmod +x mitmproxy/mitmdump mitmproxy/mitmproxy mitmproxy/mitmweb 2>/dev/null || true
    rm -f "$FILENAME"
    echo "  [OK] mitmproxy downloaded and extracted."
    echo ""
fi

# ============================================================
# STEP 2: Generate certificate
# ============================================================
if [ -f "$CERT_FILE" ]; then
    echo "[STEP 2/4] CA certificate      ... ALREADY EXISTS [SKIP]"
else
    echo "[STEP 2/4] Generating CA certificate..."

    ./mitmproxy/mitmdump --set listen_port=18943 &
    MITM_PID=$!
    sleep 3
    kill "$MITM_PID" 2>/dev/null || true
    wait "$MITM_PID" 2>/dev/null || true

    if [ ! -f "$CERT_FILE" ]; then
        echo "  [ERROR] Certificate generation failed."
        echo "  Try running ./mitmproxy/mitmdump manually once, then re-run this script."
        exit 1
    fi
    echo "  [OK] Certificate generated at $CERT_FILE"
    echo ""
fi

# ============================================================
# STEP 3: Install certificate to system trust store
# ============================================================

# Detect distro installer function
detect_and_install_cert() {
    local cert_dest=""

    # Debian/Ubuntu
    if [ -d "/usr/local/share/ca-certificates" ] && command -v update-ca-certificates &>/dev/null; then
        cert_dest="/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt"
        if [ -f "$cert_dest" ]; then
            echo "[STEP 3/4] Trusted root cert   ... ALREADY INSTALLED [SKIP]"
            return 0
        fi
        echo "[STEP 3/4] Installing certificate (Debian/Ubuntu)..."
        echo "  [NOTE] You will be prompted for your sudo password."
        sudo cp "$CERT_FILE" "$cert_dest"
        sudo update-ca-certificates
        echo "  [OK] Certificate installed."
        return 0
    fi

    # Fedora/RHEL/CentOS
    if [ -d "/etc/pki/ca-trust/source/anchors" ] && command -v update-ca-trust &>/dev/null; then
        cert_dest="/etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.pem"
        if [ -f "$cert_dest" ]; then
            echo "[STEP 3/4] Trusted root cert   ... ALREADY INSTALLED [SKIP]"
            return 0
        fi
        echo "[STEP 3/4] Installing certificate (Fedora/RHEL)..."
        echo "  [NOTE] You will be prompted for your sudo password."
        sudo cp "$CERT_FILE" "$cert_dest"
        sudo update-ca-trust
        echo "  [OK] Certificate installed."
        return 0
    fi

    # Arch
    if [ -d "/etc/ca-certificates/trust-source/anchors" ] && command -v trust &>/dev/null; then
        cert_dest="/etc/ca-certificates/trust-source/anchors/mitmproxy-ca-cert.crt"
        if [ -f "$cert_dest" ]; then
            echo "[STEP 3/4] Trusted root cert   ... ALREADY INSTALLED [SKIP]"
            return 0
        fi
        echo "[STEP 3/4] Installing certificate (Arch)..."
        echo "  [NOTE] You will be prompted for your sudo password."
        sudo cp "$CERT_FILE" "$cert_dest"
        sudo trust extract-compat
        echo "  [OK] Certificate installed."
        return 0
    fi

    # Unknown
    echo "[STEP 3/4] Trusted root cert   ... [MANUAL REQUIRED]"
    echo ""
    echo "  Could not detect your Linux distribution."
    echo "  Install the certificate manually:"
    echo "    Certificate: $CERT_FILE"
    echo ""
    echo "  Debian/Ubuntu:"
    echo "    sudo cp $CERT_FILE /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt"
    echo "    sudo update-ca-certificates"
    echo ""
    echo "  Fedora/RHEL:"
    echo "    sudo cp $CERT_FILE /etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.pem"
    echo "    sudo update-ca-trust"
    echo ""
    echo "  Arch:"
    echo "    sudo cp $CERT_FILE /etc/ca-certificates/trust-source/anchors/mitmproxy-ca-cert.crt"
    echo "    sudo trust extract-compat"
    return 1
}

detect_and_install_cert || true
echo ""

# ============================================================
# STEP 4: Run proxy
# ============================================================
if [ ! -f "$CONFIG_PATH" ]; then
    echo "[STEP 4/4] config.json          ... NOT FOUND [ERROR]"
    echo ""
    echo "  [ERROR] config.json not found in client/ folder."
    echo "  Copy config.json.sample to config.json and configure your profiles:"
    echo "    cp $CONFIG_SAMPLE $CONFIG_PATH"
    exit 1
fi

echo "[STEP 4/4] config.json          ... FOUND [OK]"
echo ""
echo "============================================================"
echo "  All checks passed! Starting proxy on port 8080..."
echo "  System proxy: 127.0.0.1:8080"
echo "  Press Ctrl+C to stop."
echo "============================================================"
echo ""

./mitmproxy/mitmdump -q -s ../proxy.py --set listen_port=8080

echo ""
echo "[INFO] Proxy server stopped."
