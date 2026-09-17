#!/bin/sh
set -eu
# Platform starts Locksmith/Keyforkd and decrypts vault values before this unit.
if [ "${CERTIFICATE_BOOTSTRAP:-}" != "certificate-service-bootstrap-v1" ]; then
    echo "Certificate-service bootstrap marker missing or invalid" >&2
    exit 1
fi
unset CERTIFICATE_BOOTSTRAP
export KEYFORKD_SOCKET_PATH=/keyforkd.sock
export PUBLIC_CERT_SERVICE_LISTEN_ADDR=0.0.0.0:8080
export CAUTION_RELEASE_CONFIG=/etc/caution/release-config.json
exec /public-cert-service
