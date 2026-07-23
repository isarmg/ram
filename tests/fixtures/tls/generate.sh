#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
umask 077

openssl req -subj '/CN=localhost' -x509 -newkey rsa:4096 \
  -keyout "$script_dir/key_pkcs8.pem" \
  -out "$script_dir/cert.pem" \
  -nodes -days 3650
openssl rsa -traditional \
  -in "$script_dir/key_pkcs8.pem" \
  -out "$script_dir/key_pkcs1.pem"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$script_dir/key_ecdsa.pem"
openssl req -subj '/CN=localhost' -x509 \
  -key "$script_dir/key_ecdsa.pem" \
  -out "$script_dir/cert_ecdsa.pem" \
  -nodes -days 3650
