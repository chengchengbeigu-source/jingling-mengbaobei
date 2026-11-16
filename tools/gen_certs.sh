#!/bin/bash
# 生成本地私有 CA + 服务器证书（SAN 含 127.0.0.1，供 WebView IP 直连校验）
set -euo pipefail
DIR="$(dirname "$0")/../server/pem"
mkdir -p "$DIR"
cd "$DIR"

# 1) CA (CN 与原版一致: MB Game Private Root CA)
if [ ! -f ca.key ]; then
  openssl genrsa -out ca.key 2048 2>/dev/null
  openssl req -x509 -new -key ca.key -sha256 -days 3650 \
    -subj "/CN=MB Game Private Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out ca.crt
  echo '[+] CA generated: ca.key / ca.crt'
fi

# 2) 服务器证书 (SAN: 127.0.0.1 + localhost + 三个原域名)
if [ ! -f server.crt ]; then
  openssl genrsa -out server.key 2048 2>/dev/null
  openssl req -new -key server.key -subj "/CN=127.0.0.1" -out server.csr
  cat > san.cnf <<'SANEOF'
subjectAltName = IP:127.0.0.1,DNS:localhost,DNS:mcbtc.cn,DNS:nalanquede.top,DNS:nalanquede.cn
extendedKeyUsage = serverAuth
SANEOF
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 3650 -sha256 -extfile san.cnf -out server.crt 2>/dev/null
  rm -f san.cnf server.csr
  echo '[+] server cert generated (SAN: IP 127.0.0.1, localhost, mcbtc.cn, ...)'
fi

openssl x509 -in ca.crt -noout -subject -dates
openssl x509 -in server.crt -noout -subject -ext subjectAltName
