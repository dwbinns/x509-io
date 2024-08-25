#!/bin/bash

# From https://stackoverflow.com/a/66502322

mkdir -p data/openssl
cd data/openssl

# key="ec:<(openssl ecparam -name prime256v1)"
key="rsa:1024"

# Create the root CA CSR and private key
openssl req \
    -new \
    -nodes \
    -sha256 \
    -newkey $key \
    -keyout root.key \
    -out root.csr \
    -subj "/CN=POC Root CA"

# Create the root CA .conf file
cat > root_openssl.conf << EOF
[ v3_attributes ]
basicConstraints     = CA:TRUE
subjectKeyIdentifier = hash
keyUsage             = digitalSignature, keyCertSign
EOF

# Create the root CA certificate
openssl x509 \
    -req \
    -sha256 \
    -signkey root.key \
    -in root.csr \
    -out root.cer \
    -days 3650 \
    -set_serial `date +%Y%m%d%H%M%S%N` \
    -extfile root_openssl.conf \
    -extensions v3_attributes

# Use the AKS namespace name for the server certificate
export SERVER_NAME=echo-namespace-1

# Create the server CSR and private key
openssl req \
    -new \
    -nodes \
    -sha256 \
    -newkey $key \
    -keyout server.key \
    -out server.csr \
    -subj "/CN=server"

# Confirm the contents of the server CSR
openssl req -in server.csr -text -noout

# Create the server .conf file
cat > server_openssl.conf << EOF
[ v3_attributes ]
basicConstraints = CA:FALSE
subjectAltName   = DNS:server
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

# Create the server certificate
openssl x509 \
    -req \
    -sha256 \
    -CA root.cer \
    -CAkey root.key \
    -in server.csr \
    -out server.cer \
    -days 3650 \
    -set_serial `date +%Y%m%d%H%M%S%N` \
    -extfile server_openssl.conf \
    -extensions v3_attributes

# Confirm the contents of the new server certificate
openssl x509 -in server.cer -text -noout

# Verify the new server certificate against the root CA
openssl verify -CAfile root.cer server.cer

# Create the client CSR and private key
openssl req \
    -new \
    -nodes \
    -sha256 \
    -newkey $key \
    -keyout client.key \
    -out client.csr \
    -subj "/CN=client"

# Confirm the contents of the client CSR
openssl req -in client.csr -text -noout

# Create the client .conf file
cat > client_openssl.conf << EOF
[ v3_attributes ]
basicConstraints = CA:FALSE
subjectAltName   = DNS:client
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Create the client certificate
openssl x509 \
    -req \
    -sha256 \
    -CA root.cer \
    -CAkey root.key \
    -in client.csr \
    -out client.cer \
    -days 3650 \
    -set_serial `date +%Y%m%d%H%M%S%N` \
    -extfile client_openssl.conf \
    -extensions v3_attributes

# Confirm the contents of the new client certificate
openssl x509 -in client.cer -text -noout

# Verify the new client certificate against the root CA
openssl verify -CAfile root.cer client.cer