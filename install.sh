#!/bin/sh
# secretenv installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ebisawa/secretenv/main/install.sh | sh

set -eu

REPO="ebisawa/secretenv"
BIN_NAME="secretenv"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s)"
case "${OS}" in
  Linux)  OS="linux" ;;
  Darwin) OS="darwin" ;;
  *)
    echo "Unsupported OS: ${OS}" >&2
    exit 1
    ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64)        ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    exit 1
    ;;
esac

# Map to release target triple
if [ "${OS}" = "darwin" ] && [ "${ARCH}" = "x86_64" ]; then
  echo "macOS x86_64 (Intel) is no longer supported. Please use an Apple Silicon Mac." >&2
  exit 1
elif [ "${OS}" = "linux" ] && [ "${ARCH}" = "x86_64" ]; then
  TARGET="x86_64-unknown-linux-gnu"
elif [ "${OS}" = "linux" ] && [ "${ARCH}" = "aarch64" ]; then
  TARGET="aarch64-unknown-linux-gnu"
elif [ "${OS}" = "darwin" ] && [ "${ARCH}" = "aarch64" ]; then
  TARGET="aarch64-apple-darwin"
else
  echo "Unsupported platform: ${OS}/${ARCH}" >&2
  exit 1
fi

# Get latest version from GitHub API
echo "Fetching latest version..."
TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
if [ -z "${TAG}" ]; then
  echo "Failed to fetch latest version" >&2
  exit 1
fi
echo "Latest version: ${TAG}"

# Download and extract
ARCHIVE="${BIN_NAME}-${TAG}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Downloading ${URL}..."
curl -fsSL "${URL}" -o "${TMP_DIR}/${ARCHIVE}"
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"

# Install binary
if [ -w "${INSTALL_DIR}" ]; then
  cp "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  chmod +x "${INSTALL_DIR}/${BIN_NAME}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo cp "${TMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
  sudo chmod +x "${INSTALL_DIR}/${BIN_NAME}"
fi

echo ""
echo "secretenv ${TAG} installed to ${INSTALL_DIR}/${BIN_NAME}"
echo "Run 'secretenv --help' to get started."
