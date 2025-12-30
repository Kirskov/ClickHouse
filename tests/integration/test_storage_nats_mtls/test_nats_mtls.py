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
    """Test mTLS connection using XML configuration"""

    # Create table using secure connection with XML config
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

    # Verify table was created successfully (connection established)
    result = instance_xml_config.query("EXISTS TABLE test.nats_mtls")
    assert result.strip() == "1"

    # Cleanup
    instance_xml_config.query("DROP TABLE test.nats_mtls")


def test_nats_mtls_table_settings(started_cluster):
    """Test mTLS connection using table-level settings"""

    # Create table with explicit mTLS settings
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
            nats_ca_cert_file = '/etc/clickhouse-server/certs/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/certs/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/certs/client-key.pem',
            nats_tls_min_version = '1.2'
        """
    )

    # Verify table was created successfully
    result = instance_table_config.query("EXISTS TABLE test.nats_mtls")
    assert result.strip() == "1"

    # Cleanup
    instance_table_config.query("DROP TABLE test.nats_mtls")


def test_nats_tls_version_13(started_cluster):
    """Test TLS 1.3 configuration"""

    instance_table_config.query(
        """
        CREATE TABLE test.nats_tls13
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.tls13',
            nats_format = 'JSONEachRow',
            nats_secure = 1,
            nats_ca_cert_file = '/etc/clickhouse-server/certs/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/certs/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/certs/client-key.pem',
            nats_tls_min_version = '1.3'
        """
    )

    result = instance_table_config.query("EXISTS TABLE test.nats_tls13")
    assert result.strip() == "1"

    instance_table_config.query("DROP TABLE test.nats_tls13")


def test_nats_cipher_list(started_cluster):
    """Test cipher list configuration"""

    instance_table_config.query(
        """
        CREATE TABLE test.nats_ciphers
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.ciphers',
            nats_format = 'JSONEachRow',
            nats_secure = 1,
            nats_ca_cert_file = '/etc/clickhouse-server/certs/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/certs/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/certs/client-key.pem',
            nats_cipher_list = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384'
        """
    )

    result = instance_table_config.query("EXISTS TABLE test.nats_ciphers")
    assert result.strip() == "1"

    instance_table_config.query("DROP TABLE test.nats_ciphers")


def test_nats_curve_list(started_cluster):
    """Test elliptic curve list configuration"""

    instance_table_config.query(
        """
        CREATE TABLE test.nats_curves
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.curves',
            nats_format = 'JSONEachRow',
            nats_secure = 1,
            nats_ca_cert_file = '/etc/clickhouse-server/certs/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/certs/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/certs/client-key.pem',
            nats_curve_list = 'prime256v1:secp384r1'
        """
    )

    result = instance_table_config.query("EXISTS TABLE test.nats_curves")
    assert result.strip() == "1"

    instance_table_config.query("DROP TABLE test.nats_curves")


def test_nats_prefer_server_ciphers(started_cluster):
    """Test preferServerCiphers configuration"""

    instance_table_config.query(
        """
        CREATE TABLE test.nats_prefer_server
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.prefer_server',
            nats_format = 'JSONEachRow',
            nats_secure = 1,
            nats_ca_cert_file = '/etc/clickhouse-server/certs/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/certs/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/certs/client-key.pem',
            nats_prefer_server_ciphers = 1
        """
    )

    result = instance_table_config.query("EXISTS TABLE test.nats_prefer_server")
    assert result.strip() == "1"

    instance_table_config.query("DROP TABLE test.nats_prefer_server")


def test_nats_all_tls_options(started_cluster):
    """Test all TLS options combined"""

    instance_table_config.query(
        """
        CREATE TABLE test.nats_all_tls
        (
            id UInt64,
            message String
        )
        ENGINE = NATS
        SETTINGS
            nats_url = 'nats://nats1:4444',
            nats_subjects = 'test.all_tls',
            nats_format = 'JSONEachRow',
            nats_secure = 1,
            nats_ca_cert_file = '/etc/clickhouse-server/certs/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/certs/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/certs/client-key.pem',
            nats_tls_min_version = '1.3',
            nats_cipher_list = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384',
            nats_curve_list = 'prime256v1:secp384r1',
            nats_prefer_server_ciphers = 1
        """
    )

    result = instance_table_config.query("EXISTS TABLE test.nats_all_tls")
    assert result.strip() == "1"

    instance_table_config.query("DROP TABLE test.nats_all_tls")


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
            nats_ca_cert_file = '/etc/clickhouse-server/certs/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/certs/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/certs/client-key.pem',
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
            nats_ca_cert_file = '/etc/clickhouse-server/certs/ca-cert.pem',
            nats_client_cert_file = '/etc/clickhouse-server/certs/client-cert.pem',
            nats_client_key_file = '/etc/clickhouse-server/certs/client-key.pem'
        """
    )

    # Insert test data
    instance_table_config.query(
        """
        INSERT INTO test.nats_producer VALUES (1, 'Hello mTLS'), (2, 'Secure Connection')
        """
    )

    # Wait for messages to be consumed
    time.sleep(5)

    # Verify messages were received
    result = instance_table_config.query("SELECT count() FROM test.nats_view")
    assert int(result.strip()) == 2

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
    """Test that connection fails when client certificate is missing"""

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
                nats_ca_cert_file = '/etc/clickhouse-server/certs/ca-cert.pem'
            """
        )


def test_nats_invalid_ca_cert_fails(started_cluster):
    """Test that connection fails with invalid CA certificate"""

    with pytest.raises(Exception):
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
                nats_ca_cert_file = '/etc/clickhouse-server/certs/invalid-ca.pem',
                nats_client_cert_file = '/etc/clickhouse-server/certs/client-cert.pem',
                nats_client_key_file = '/etc/clickhouse-server/certs/client-key.pem'
            """
        )
