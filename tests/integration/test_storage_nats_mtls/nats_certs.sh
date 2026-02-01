#!/bin/bash
# Generate/copy certificates for NATS mTLS integration tests
set -euo pipefail

CERT_DIR="${NATS_CERT_DIR}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Create directory structure expected by docker_compose_nats.yml
mkdir -p "${CERT_DIR}/ca"
mkdir -p "${CERT_DIR}/nats"

if [ -f "${SCRIPT_DIR}/certs/ca-cert.pem" ]; then
    # Use pre-generated test certificates
    cp "${SCRIPT_DIR}/certs/ca-cert.pem" "${CERT_DIR}/ca/ca-cert.pem"
    cp "${SCRIPT_DIR}/certs/server-cert.pem" "${CERT_DIR}/nats/server-cert.pem"
    cp "${SCRIPT_DIR}/certs/server-key.pem" "${CERT_DIR}/nats/server-key.pem"
    cp "${SCRIPT_DIR}/certs/client-cert.pem" "${CERT_DIR}/nats/client-cert.pem"
    cp "${SCRIPT_DIR}/certs/client-key.pem" "${CERT_DIR}/nats/client-key.pem"
    cp "${SCRIPT_DIR}/certs/ca-cert.pem" "${CERT_DIR}/nats/ca-cert.pem"
    echo "Copied pre-generated certificates to ${CERT_DIR}"
else
    # Generate fresh certificates
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${CERT_DIR}/ca/ca-key.pem" \
        -out "${CERT_DIR}/ca/ca-cert.pem" \
        -days 365 \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=TestCA" 2>/dev/null

    openssl req -newkey rsa:2048 -nodes \
        -keyout "${CERT_DIR}/nats/server-key.pem" \
        -out "${CERT_DIR}/nats/server.csr" \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=nats1" 2>/dev/null

    cat > "${CERT_DIR}/nats/server-ext.cnf" <<EOF
[v3_req]
subjectAltName = DNS:nats1, DNS:localhost, IP:127.0.0.1
EOF

    openssl x509 -req \
        -in "${CERT_DIR}/nats/server.csr" \
        -CA "${CERT_DIR}/ca/ca-cert.pem" \
        -CAkey "${CERT_DIR}/ca/ca-key.pem" \
        -CAcreateserial \
        -out "${CERT_DIR}/nats/server-cert.pem" \
        -days 365 \
        -extfile "${CERT_DIR}/nats/server-ext.cnf" \
        -extensions v3_req 2>/dev/null

    openssl req -newkey rsa:2048 -nodes \
        -keyout "${CERT_DIR}/nats/client-key.pem" \
        -out "${CERT_DIR}/nats/client.csr" \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=clickhouse-client" 2>/dev/null

    openssl x509 -req \
        -in "${CERT_DIR}/nats/client.csr" \
        -CA "${CERT_DIR}/ca/ca-cert.pem" \
        -CAkey "${CERT_DIR}/ca/ca-key.pem" \
        -CAcreateserial \
        -out "${CERT_DIR}/nats/client-cert.pem" \
        -days 365 2>/dev/null

    cp "${CERT_DIR}/ca/ca-cert.pem" "${CERT_DIR}/nats/ca-cert.pem"

    mkdir -p "${SCRIPT_DIR}/certs"
    cp "${CERT_DIR}/ca/ca-cert.pem" "${SCRIPT_DIR}/certs/ca-cert.pem"
    cp "${CERT_DIR}/nats/server-cert.pem" "${SCRIPT_DIR}/certs/server-cert.pem"
    cp "${CERT_DIR}/nats/server-key.pem" "${SCRIPT_DIR}/certs/server-key.pem"
    cp "${CERT_DIR}/nats/client-cert.pem" "${SCRIPT_DIR}/certs/client-cert.pem"
    cp "${CERT_DIR}/nats/client-key.pem" "${SCRIPT_DIR}/certs/client-key.pem"

    rm -f "${CERT_DIR}/nats/server.csr" "${CERT_DIR}/nats/client.csr" \
          "${CERT_DIR}/nats/server-ext.cnf" "${CERT_DIR}/ca/ca-cert.srl"

    echo "Generated fresh certificates in ${CERT_DIR}"
fi

# Copy NATS server config (with handshake_first and mTLS enabled)
cp "${SCRIPT_DIR}/nats-server.conf" "${CERT_DIR}/nats/nats-server.conf"
echo "Copied NATS server config to ${CERT_DIR}/nats/"
