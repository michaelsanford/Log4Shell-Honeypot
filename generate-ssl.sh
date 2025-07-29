#!/bin/bash

mkdir -p ssl

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ssl/key.pem \
    -out ssl/cert.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=honeypot.local"

chmod 600 ssl/key.pem
chmod 644 ssl/cert.pem

echo "SSL certificates generated in ssl/ directory"
