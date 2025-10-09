#!/bin/bash
set -e

# ===========================
# Config
# ===========================
IP_ADDR="192.168.153.128"   # Đổi IP này thành IP của server bạn
DAYS=365                 # Hạn của server cert
CA_DAYS=3650             # Hạn của CA

# ===========================
# Tạo thư mục output
# ===========================
OUTDIR="certs"
mkdir -p $OUTDIR
cd $OUTDIR

# ===========================
# Tạo CA
# ===========================
echo "[*] Tạo CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days $CA_DAYS \
  -out ca.pem -subj "/CN=LocalTestCA"

# ===========================
# File cấu hình SAN cho server
# ===========================
cat > server.cnf <<EOF
[req]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt = no

[req_distinguished_name]
CN = $IP_ADDR

[req_ext]
subjectAltName = @alt_names

[alt_names]
IP.1 = $IP_ADDR
EOF

# ===========================
# Server key + CSR
# ===========================
echo "[*] Tạo server key + CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config server.cnf

# ===========================
# Ký cert bằng CA
# ===========================
echo "[*] Ký cert..."
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.crt -days $DAYS -sha256 -extensions req_ext -extfile server.cnf

# ===========================
# Hoàn tất
# ===========================
echo "[+] Done!"
echo "CA cert   : $(pwd)/ca.pem"
echo "Server key: $(pwd)/server.key"
echo "Server crt: $(pwd)/server.crt"

cp ca.pem /home/ubuntu/lib/linux-edrkvq/configs/ca_self.pem
cd ..
