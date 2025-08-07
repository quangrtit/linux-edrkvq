#!/bin/bash
set -e

DEB_FILE="SentinelEDR-1.0.0-linux-x86_64.deb"

# Đảm bảo file .deb tồn tại
if [ ! -f "$DEB_FILE" ]; then
    echo "[-] Không tìm thấy gói .deb: $DEB_FILE"
    exit 1
fi

echo "[*] Cài đặt SentinelEDR từ $DEB_FILE..."
sudo dpkg -i "$DEB_FILE"

echo "[*] Reload systemd daemon..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload

echo "[*] Enable và start dịch vụ SentinelEDR..."
sudo systemctl enable SentinelEDR.service
sudo systemctl restart SentinelEDR.service

echo "[+] Cài đặt thành công và dịch vụ đã khởi động!"
