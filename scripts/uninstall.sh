#!/bin/bash

# Set variables
BINARY="gocryptic"
INSTALL_DIR="/usr/local/bin"

# Check if the binary exists in the install directory
if [ -f "$INSTALL_DIR/$BINARY" ]; then
    echo "Removing $BINARY from $INSTALL_DIR..."
    # Check if sudo is needed
    if [ "$EUID" -ne 0 ]; then
        sudo rm "$INSTALL_DIR/$BINARY"
    else
        rm "$INSTALL_DIR/$BINARY"
    fi
    echo "$BINARY uninstalled successfully!"
else
    echo "$BINARY not found in $INSTALL_DIR."
fi
