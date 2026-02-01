"""Tests for NATS mTLS authentication and TLS configuration"""

import pytest
import time
import logging
from helpers.cluster import ClickHouseCluster


cluster = ClickHouseCluster(__file__)

# Instance with mTLS configuration via XML
instance_xml_config = cluster.add_instance(
    "instance_xml",
    main_configs=[
        "configs/nats_mtls.xml",
        "certs/ca-cert.pem",
        "certs/client-cert.pem",
        "certs/client-key.pem",
    ],
    user_configs=["configs/users.xml"],
    with_nats=True,
)

# Instance without XML config (will use table settings)
instance_table_config = cluster.add_instance(
    "instance_table",
    main_configs=[
        "certs/ca-cert.pem",
        "certs/client-cert.pem",
        "certs/client-key.pem",
    ],
    user_configs=["configs/users.xml"],
    with_nats=True,
)


@pytest.fixture(scope="module")
def started_cluster():
    try:
        cluster.start()
        yield cluster
    finally:
        cluster.shutdown()


@pytest.fixture(autouse=True)
def setup_teardown(started_cluster):
    """Setup and teardown for each test"""
    instance_xml_config.query("DROP DATABASE IF EXISTS test SYNC; CREATE DATABASE test;")
    instance_table_config.query("DROP DATABASE IF EXISTS test SYNC; CREATE DATABASE test;")
    yield  # run test
    instance_xml_config.query("DROP DATABASE IF EXISTS test SYNC;")
    instance_table_config.query("DROP DATABASE IF EXISTS test SYNC;")


def test_nats_mtls_xml_config(started_cluster):
    """Test mTLS connection using XML configuration (certs + handshake_first from XML)"""

    instance_xml_config.query(
        """
        CREATE TABLE test.nats_mtls
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.mtls.xml',
            nats_format = 'JSONEachRow',
            nats_secure = 1
        """
    )

    result = instance_xml_config.query("EXISTS TABLE test.nats_mtls")
    assert result.strip() == "1"

    instance_xml_config.query("DROP TABLE test.nats_mtls")


def test_nats_mtls_table_settings(started_cluster):
    """Test mTLS connection using table-level settings"""

    instance_table_config.query(
        """
        CREATE TABLE test.nats_mtls
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.mtls.table',
            nats_format = 'JSONEachRow',
            nats_secure = 1,
            nats_ca_cert_file = '/etc/clickhouse-server/config.d/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/config.d/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/config.d/client-key.pem',
            nats_tls_handshake_first = 1
        """
    )

    result = instance_table_config.query("EXISTS TABLE test.nats_mtls")
    assert result.strip() == "1"

    instance_table_config.query("DROP TABLE test.nats_mtls")


def test_nats_mtls_publish_consume(started_cluster):
    """Test publishing and consuming messages over mTLS connection"""

    # Create consumer table
    instance_table_config.query(
        """
        CREATE TABLE test.nats_consumer
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.publish_consume',
            nats_format = 'JSONEachRow',
            nats_secure = 1,
            nats_ca_cert_file = '/etc/clickhouse-server/config.d/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/config.d/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/config.d/client-key.pem',
            nats_tls_handshake_first = 1,
            nats_num_consumers = 1
        """
    )

    # Create materialized view to store messages
    instance_table_config.query(
        """
        CREATE TABLE test.nats_view
        (
            id UInt64,
            message String
        )
        ENGINE = MergeTree()
        ORDER BY id
        """
    )

    instance_table_config.query(
        """
        CREATE MATERIALIZED VIEW test.nats_mv TO test.nats_view AS
        SELECT id, message FROM test.nats_consumer
        """
    )

    # Create producer table
    instance_table_config.query(
        """
        CREATE TABLE test.nats_producer
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.publish_consume',
            nats_format = 'JSONEachRow',
            nats_secure = 1,
            nats_ca_cert_file = '/etc/clickhouse-server/config.d/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/config.d/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/config.d/client-key.pem',
            nats_tls_handshake_first = 1
        """
    )

    # Insert test data
    instance_table_config.query(
        """
        INSERT INTO test.nats_producer VALUES (1, 'Hello mTLS'), (2, 'Secure Connection')
        """
    )

    # Wait for messages to be consumed (retry up to 30s)
    deadline = time.monotonic() + 30
    count = 0
    while time.monotonic() < deadline:
        result = instance_table_config.query("SELECT count() FROM test.nats_view")
        count = int(result.strip())
        if count >= 2:
            break
        time.sleep(1)

    assert count == 2, f"Expected 2 messages but got {count}"

    # Verify message content
    result = instance_table_config.query(
        "SELECT id, message FROM test.nats_view ORDER BY id"
    )
    assert "1\tHello mTLS" in result
    assert "2\tSecure Connection" in result

    # Cleanup
    instance_table_config.query("DROP TABLE test.nats_mv")
    instance_table_config.query("DROP TABLE test.nats_view")
    instance_table_config.query("DROP TABLE test.nats_consumer")
    instance_table_config.query("DROP TABLE test.nats_producer")


def test_nats_missing_client_cert_fails(started_cluster):
    """Test that connection fails when client certificate is missing (server requires mTLS)"""

    with pytest.raises(Exception):
        instance_table_config.query(
            """
            CREATE TABLE test.nats_no_cert
            (
                id UInt64,
                message String
            )
            ENGINE = NATS
            SETTINGS
                nats_url = 'nats://nats1:4444',
                nats_subjects = 'test.no_cert',
                nats_format = 'JSONEachRow',
                nats_secure = 1,
                nats_ca_cert_file = '/etc/clickhouse-server/config.d/ca-cert.pem',
                nats_tls_handshake_first = 1
            """
        )


def test_nats_invalid_ca_cert_fails(started_cluster):
    """Test that connection fails with invalid CA certificate.

    ClickHouse creates the table successfully but the NATS connection
    fails at runtime when the CA cert is wrong. We verify this by
    checking the system.nats_consumers status shows an error.
    """

    # Table creation succeeds (validation is deferred to connection time)
    instance_table_config.query(
        """
        CREATE TABLE test.nats_bad_ca
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.bad_ca',
            nats_format = 'JSONEachRow',
            nats_secure = 1,
            nats_ca_cert_file = '/etc/clickhouse-server/config.d/invalid-ca.pem',
            nats_client_cert_file = '/etc/clickhouse-server/config.d/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/config.d/client-key.pem',
            nats_tls_handshake_first = 1
        """
    )

    # Give it time to attempt the connection
    time.sleep(5)

    # Check that the NATS engine logged connection errors
    result = instance_table_config.query(
        "SELECT count() FROM system.text_log WHERE level = 'Error' "
        "AND message LIKE '%nats%' AND event_time > now() - 30"
    )
    error_count = int(result.strip())
    assert error_count > 0, "Expected NATS connection errors with invalid CA cert"

    instance_table_config.query("DROP TABLE test.nats_bad_ca")
