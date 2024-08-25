#!/bin/sh
set -e

mkdir -p data/x509
cd data/x509

rm -rf root-ec root-rsa server-rsa server-ec server-rsa-ec server-ec-rsa

x509-io generate secp256r1 SHA-256 root-ec - /CN=issuer ca 1D
x509-io generate rsa4096 SHA-512 root-rsa - /CN=issuer ca 1D

echo 'EC/EC'
x509-io generate secp256r1 SHA-256 server-ec root-ec /CN=subject server 1D server.internal
x509-io verify root-ec/cert.pem server-ec/cert.pem
openssl verify -trusted root-ec/cert.pem server-ec/cert.pem

echo 'EC/RSA'
x509-io generate secp256r1 SHA-256 server-ec-rsa root-rsa /CN=subject server 1D server.internal
x509-io verify root-rsa/cert.pem server-ec-rsa/cert.pem
openssl verify -trusted root-rsa/cert.pem server-ec-rsa/cert.pem

echo 'RSA/EC'
x509-io generate rsa4096 SHA-256 server-rsa-ec root-ec /CN=subject server 1D server.internal
x509-io verify root-ec/cert.pem server-rsa-ec/cert.pem
openssl verify -trusted root-ec/cert.pem server-rsa-ec/cert.pem

echo 'RSA/RSA'
x509-io generate rsa4096 SHA-512 server-rsa root-rsa /CN=subject server 1D server.internal
x509-io verify root-rsa/cert.pem server-rsa/cert.pem
openssl verify -trusted root-rsa/cert.pem server-rsa/cert.pem
