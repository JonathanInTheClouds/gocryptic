#!/bin/bash

# Set variables
REPO="JonathanInTheClouds/gocryptic"
VERSION="v1.0.0"
BINARY="gocryptic"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS=$(uname | tr '[:upper:]' '[:lower:]')

# Map `darwin` to `mac`, `linux` remains unchanged
if [[ "$OS" == "darwin" ]]; then
    OS="mac"
elif [[ "$OS" != "linux" ]]; then
    echo "Unsupported OS: $OS"
    exit 1
fi

# Construct the download URL based on OS
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$BINARY-$OS"

# Download the binary
echo "Downloading $BINARY from $DOWNLOAD_URL..."
curl -L "$DOWNLOAD_URL" -o "$BINARY"

# Make it executable
chmod +x "$BINARY"

# Determine if sudo is needed (skip if running as root)
if [ "$EUID" -ne 0 ]; then
    SUDO='sudo'
else
    SUDO=''
fi

# Move the binary to the install directory
echo "Installing $BINARY to $INSTALL_DIR..."
$SUDO mv "$BINARY" "$INSTALL_DIR"

# Verify installation
if command -v $BINARY &> /dev/null; then
    echo "$BINARY installed successfully!"
else
    echo "Installation failed."
    exit 1
fi
