#!/bin/bash
set -e

echo "[*] Dừng và tắt dịch vụ SentinelEDR..."
sudo systemctl stop SentinelEDR.service || true
sudo systemctl disable SentinelEDR.service || true

echo "[*] Xóa gói SentinelEDR..."
sudo dpkg -r sentinel-edr || sudo dpkg --purge sentinel-edr

echo "[*] Reload systemd daemon..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload

echo "[*] Xóa file service nếu còn..."
sudo rm -f /etc/systemd/system/SentinelEDR.service
sudo rm -f /lib/systemd/system/SentinelEDR.service

echo "[*] Xóa cấu hình..."
sudo rm -rf /etc/SentinelEDR/
sudo rm -rf /var/lib/SentinelEDR/

echo "[+] Gỡ cài đặt hoàn tất!"
