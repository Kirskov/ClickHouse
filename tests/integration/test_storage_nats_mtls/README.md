# NATS mTLS Integration Tests

Integration tests for NATS mTLS (mutual TLS) authentication in ClickHouse.

## Running Tests

```bash
cd /home/agricourt/ClickHouse/tests/integration
pytest test_storage_nats_mtls/test_nats_mtls.py -v
```

## Test Coverage

- mTLS connection via XML configuration
- mTLS connection via table settings
- TLS 1.2 and 1.3 support
- Cipher list configuration
- Elliptic curve configuration
- Server cipher preference
- Publish/consume over mTLS
- Error handling for invalid certificates

## Certificates

Pre-generated test certificates are included in the `certs/` directory (copied from MySQL test certificates for consistency).
