#!/usr/bin/env bash
# GoCryptic installer
# Usage: curl -fsSL https://raw.githubusercontent.com/gocryptic/gocryptic/main/install.sh | bash
# Or:    bash install.sh [--version v1.0.0] [--dir /usr/local/bin]

set -euo pipefail

REPO="gocryptic/gocryptic"
INSTALL_DIR="${GCRY_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="gocryptic"
VERSION=""

# ── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}  →${NC}  $*"; }
success() { echo -e "${GREEN}  ✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}  ⚠${NC}  $*"; }
die()     { echo -e "${RED}  ✗${NC}  $*" >&2; exit 1; }

# ── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dir)     INSTALL_DIR="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: install.sh [--version v1.2.3] [--dir /usr/local/bin]"
      echo ""
      echo "  --version   Install a specific release (default: latest)"
      echo "  --dir       Installation directory (default: /usr/local/bin)"
      echo ""
      echo "  Environment variables:"
      echo "    GCRY_INSTALL_DIR   Override installation directory"
      exit 0
      ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# ── Detect OS ───────────────────────────────────────────────────────────────
detect_os() {
  case "$(uname -s)" in
    Linux*)   echo "linux"   ;;
    Darwin*)  echo "darwin"  ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) die "Unsupported operating system: $(uname -s)" ;;
  esac
}

# ── Detect architecture ──────────────────────────────────────────────────────
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)    echo "amd64" ;;
    arm64|aarch64)   echo "arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
}

# ── Detect download tool ─────────────────────────────────────────────────────
detect_downloader() {
  if command -v curl &>/dev/null; then
    echo "curl"
  elif command -v wget &>/dev/null; then
    echo "wget"
  else
    die "Neither curl nor wget found. Please install one and try again."
  fi
}

download() {
  local url="$1" dest="$2" tool="$3"
  case "$tool" in
    curl) curl -fsSL --progress-bar "$url" -o "$dest" ;;
    wget) wget -q --show-progress "$url" -O "$dest" ;;
  esac
}

# ── Fetch latest version from GitHub ────────────────────────────────────────
fetch_latest_version() {
  local tool="$1"
  local url="https://api.github.com/repos/${REPO}/releases/latest"
  case "$tool" in
    curl) curl -fsSL "$url" | grep '"tag_name"' | sed 's/.*"tag_name": *"\(.*\)".*/\1/' ;;
    wget) wget -qO- "$url"  | grep '"tag_name"' | sed 's/.*"tag_name": *"\(.*\)".*/\1/' ;;
  esac
}

# ── Verify checksum ──────────────────────────────────────────────────────────
verify_checksum() {
  local binary="$1" checksum_file="$2" binary_name="$3"
  if command -v sha256sum &>/dev/null; then
    grep "$binary_name" "$checksum_file" | sha256sum -c - &>/dev/null \
      && return 0 || return 1
  elif command -v shasum &>/dev/null; then
    grep "$binary_name" "$checksum_file" | shasum -a 256 -c - &>/dev/null \
      && return 0 || return 1
  else
    warn "No sha256 tool found — skipping checksum verification"
    return 0
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo -e "  ${CYAN}GoCryptic Installer${NC}"
  echo "  ────────────────────────────────"
  echo ""

  OS=$(detect_os)
  ARCH=$(detect_arch)
  DOWNLOADER=$(detect_downloader)

  # Resolve version
  if [[ -z "$VERSION" ]]; then
    info "Fetching latest release..."
    VERSION=$(fetch_latest_version "$DOWNLOADER")
    [[ -z "$VERSION" ]] && die "Could not determine latest version. Use --version to specify one."
  fi

  info "Version  : ${VERSION}"
  info "Platform : ${OS}/${ARCH}"
  info "Install  : ${INSTALL_DIR}"
  echo ""

  # Build asset name
  SUFFIX=""
  [[ "$OS" == "windows" ]] && SUFFIX=".exe"
  ASSET_NAME="gocryptic-${OS}-${ARCH}${SUFFIX}"
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

  TMPDIR=$(mktemp -d)
  trap 'rm -rf "$TMPDIR"' EXIT

  # Download binary
  info "Downloading ${ASSET_NAME}..."
  download "${BASE_URL}/${ASSET_NAME}" "${TMPDIR}/${ASSET_NAME}" "$DOWNLOADER"

  # Download and verify checksum
  info "Verifying checksum..."
  download "${BASE_URL}/checksums.txt" "${TMPDIR}/checksums.txt" "$DOWNLOADER"
  if verify_checksum "${TMPDIR}/${ASSET_NAME}" "${TMPDIR}/checksums.txt" "${ASSET_NAME}"; then
    success "Checksum verified"
  else
    die "Checksum verification failed — aborting installation"
  fi

  # Install
  chmod +x "${TMPDIR}/${ASSET_NAME}"

  if [[ ! -d "$INSTALL_DIR" ]]; then
    info "Creating directory ${INSTALL_DIR}..."
    mkdir -p "$INSTALL_DIR" 2>/dev/null || sudo mkdir -p "$INSTALL_DIR"
  fi

  DEST="${INSTALL_DIR}/${BINARY_NAME}${SUFFIX}"

  if [[ -w "$INSTALL_DIR" ]]; then
    mv "${TMPDIR}/${ASSET_NAME}" "$DEST"
  else
    info "Requesting sudo to install to ${INSTALL_DIR}..."
    sudo mv "${TMPDIR}/${ASSET_NAME}" "$DEST"
  fi

  echo ""
  success "Installed gocryptic ${VERSION} → ${DEST}"
  echo ""

  # Verify the installed binary works
  if command -v gocryptic &>/dev/null; then
    success "gocryptic is in your PATH and ready to use"
    echo ""
    echo "  Run: gocryptic --help"
  else
    warn "${INSTALL_DIR} is not in your PATH."
    echo ""
    echo "  Add it with:"
    echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
    echo ""
    echo "  Or run it directly:"
    echo "    ${DEST} --help"
  fi

  echo ""
}

main "$@"
