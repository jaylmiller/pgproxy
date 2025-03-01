openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out server.csr -subj "/CN=*.db.local/O=My Server/C=US"
cat > server_ext.cnf << EOF
subjectAltName = DNS:*.db.local, DNS:localhost, IP:127.0.0.1
EOF
openssl x509 -req -in server.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key \
  -CAcreateserial -out server.crt -days 825 -sha256 -extfile server_ext.cnf