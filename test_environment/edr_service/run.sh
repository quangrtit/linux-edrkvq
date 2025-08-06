#!/bin/bash

set -e  # Stop script on any error

# Compile binaries
# echo "[*] Building binaries..."
# clang edr_launcher.c -o /usr/local/sbin/edr_launcher
# clang edr_main.c -o /usr/local/sbin/edr_main
# clang edr_control.c -o /usr/local/sbin/edr_control

# # Set correct permissions
# chmod 755 /usr/local/sbin/edr_launcher /usr/local/sbin/edr_main /usr/local/sbin/edr_control

# # Install systemd service
# echo "[*] Installing systemd service..."
# sudo cp edr.service /etc/systemd/system/edr.service

# # Reload systemd and enable/start service
# echo "[*] Reloading systemd..."
# sudo systemctl daemon-reload
# sudo systemctl enable edr --now

# echo "[+] EDR service installed and running!"


echo "[*] Stopping EDR service if running..."
sudo systemctl stop edr || true
sudo systemctl disable edr || true

echo "[*] Removing systemd service file..."
sudo rm -f /etc/systemd/system/edr.service
sudo systemctl daemon-reload

echo "[*] Removing EDR binaries..."
sudo rm -f /usr/local/sbin/edr_launcher
sudo rm -f /usr/local/sbin/edr_main
sudo rm -f /usr/local/sbin/edr_control

echo "[*] Cleaning up IPC socket files..."
sudo rm -f /tmp/edr_control.sock
ps aux | grep edr_main