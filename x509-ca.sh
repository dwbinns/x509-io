#!/bin/sh
set -e

mkdir -p data/x509
cd data/x509

rm -rf root-ec root-rsa server-rsa server-ec server-rsa-ec server-ec-rsa

node ../../cli.js generate secp256r1 SHA-256 root-ec - /CN=issuer ca 1D
node ../../cli.js generate RSA-1024 SHA-512 root-rsa - /CN=issuer ca 1D

echo 'EC/EC'
node ../../cli.js generate secp256r1 SHA-256 server-ec root-ec /CN=subject server 1D server.internal
node ../../cli.js verify root-ec/cert.pem server-ec/cert.pem
openssl verify -trusted root-ec/cert.pem server-ec/cert.pem

echo 'EC/RSA'
node ../../cli.js generate secp256r1 SHA-256 server-ec-rsa root-rsa /CN=subject server 1D server.internal
node ../../cli.js verify root-rsa/cert.pem server-ec-rsa/cert.pem
openssl verify -trusted root-rsa/cert.pem server-ec-rsa/cert.pem

echo 'RSA/EC'
node ../../cli.js generate RSA-1024 SHA-256 server-rsa-ec root-ec /CN=subject server 1D server.internal
node ../../cli.js verify root-ec/cert.pem server-rsa-ec/cert.pem
openssl verify -trusted root-ec/cert.pem server-rsa-ec/cert.pem

echo 'RSA/RSA'
node ../../cli.js generate RSA-1024 SHA-512 server-rsa root-rsa /CN=subject server 1D server.internal
node ../../cli.js verify root-rsa/cert.pem server-rsa/cert.pem
openssl verify -trusted root-rsa/cert.pem server-rsa/cert.pem
