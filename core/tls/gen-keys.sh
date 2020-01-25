#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <host>"
    exit 1
fi

host="$1"
name="$(uuidgen)"

# CA
echo -e "[+] Generating CA cert..."
echo -e "\u001b[32m CA/server keys' password is 'aaaa', or edit it in ./tls/dev.password\u001b[0m"
openssl genrsa -des3 -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt

# server key
echo -e "\n\n[+] Generating server key..."
bash ./genkey-with-ip-san.sh "$name" "$name.com" "$host"
mv "./${name}-cert.pem" ./emp3r0r-cert.pem
mv "./${name}-key.pem" ./emp3r0r-key.pem
