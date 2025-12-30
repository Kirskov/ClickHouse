#include <Storages/NATS/NATSConnection.h>

#include <IO/WriteHelpers.h>
#include <Common/logger_useful.h>

#include <boost/algorithm/string/join.hpp>

#include <openssl/ssl.h>
#include <openssl/err.h>


namespace DB
{

/// disconnectedCallback may be called after connection destroy
LoggerPtr NATSConnection::callback_logger = getLogger("NATSConnection callback");

/// SSL/TLS context configuration callback
static natsStatus configureTLSContext(SSL_CTX* ctx, void* closure)
{
    auto* config = static_cast<const NATSConfiguration*>(closure);

    // Configure TLS version
    if (!config->tls_min_version.empty())
    {
        if (config->tls_min_version == "1.3")
        {
            SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        }
        else if (config->tls_min_version == "1.2")
        {
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        }
    }

    // Configure cipher list (OpenSSL notation, colon-separated)
    if (!config->cipher_list.empty())
    {
        // Set TLS 1.2 and below ciphers
        if (SSL_CTX_set_cipher_list(ctx, config->cipher_list.c_str()) != 1)
        {
            return NATS_SSL_ERROR;
        }
        // Also try to set TLS 1.3 ciphersuites
        SSL_CTX_set_ciphersuites(ctx, config->cipher_list.c_str());
    }

    // Configure elliptic curves (colon-separated)
    if (!config->curve_list.empty())
    {
        if (SSL_CTX_set1_groups_list(ctx, config->curve_list.c_str()) != 1)
        {
            // Fallback for older OpenSSL versions
            #ifndef OPENSSL_NO_EC
            if (SSL_CTX_set1_curves_list(ctx, config->curve_list.c_str()) != 1)
            {
                return NATS_SSL_ERROR;
            }
            #endif
        }
    }

    // Configure server cipher preference
    if (config->prefer_server_ciphers)
    {
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    return NATS_OK;
}

NATSConnection::NATSConnection(const NATSConfiguration & configuration_, LoggerPtr log_, NATSOptionsPtr options_)
    : configuration(configuration_)
    , log(std::move(log_))
    , options(std::move(options_))
    , connection(nullptr, &natsConnection_Destroy)
{
    if (!configuration.username.empty() && !configuration.password.empty())
        natsOptions_SetUserInfo(options.get(), configuration.username.c_str(), configuration.password.c_str());
    if (!configuration.token.empty())
        natsOptions_SetToken(options.get(), configuration.token.c_str());
    if (!configuration.credential_file.empty())
        natsOptions_SetUserCredentialsFromFiles(options.get(), configuration.credential_file.c_str(), nullptr);

    if (configuration.secure)
    {
        natsOptions_SetSecure(options.get(), true);

        // Configure mTLS if certificate files are provided
        if (!configuration.ca_cert_file.empty())
        {
            LOG_DEBUG(log, "Setting CA certificate file: {}", configuration.ca_cert_file);
            natsOptions_LoadCATrustedCertificates(options.get(), configuration.ca_cert_file.c_str());
        }

        if (!configuration.client_cert_file.empty() && !configuration.client_key_file.empty())
        {
            LOG_DEBUG(log, "Setting client certificate and key files for mTLS");
            natsOptions_LoadCertificatesChain(
                options.get(),
                configuration.client_cert_file.c_str(),
                configuration.client_key_file.c_str());
        }

        // Set SSL/TLS context callback for advanced TLS configuration
        // This allows us to configure TLS version, cipher list, and curves using OpenSSL directly
        if (!configuration.tls_min_version.empty() || !configuration.cipher_list.empty() || !configuration.curve_list.empty() || configuration.prefer_server_ciphers)
        {
            LOG_DEBUG(log, "Configuring advanced TLS settings - Version: {}, Cipher list: {}, Curve list: {}, Prefer server ciphers: {}",
                     configuration.tls_min_version, configuration.cipher_list, configuration.curve_list, configuration.prefer_server_ciphers);

            // Pass the configuration as closure to the SSL context callback
            natsOptions_SetSSLCtx(options.get(), const_cast<NATSConfiguration*>(&configuration));
            natsOptions_SetSSLCtxCB(options.get(), configureTLSContext, const_cast<NATSConfiguration*>(&configuration));
        }
    }

    // use CLICKHOUSE_NATS_TLS_SECURE=0 env var to skip TLS verification of server cert
    const char * val = std::getenv("CLICKHOUSE_NATS_TLS_SECURE"); // NOLINT(concurrency-mt-unsafe) // this is safe on Linux glibc/Musl, but potentially not safe on other platforms
    std::string tls_secure = val == nullptr ? std::string("1") : std::string(val);
    if (tls_secure == "0")
    {
        natsOptions_SkipServerVerification(options.get(), true);
    }

    if (!configuration.url.empty())
    {
        natsOptions_SetURL(options.get(), configuration.url.c_str());
    }
    else
    {
        std::vector<const char *> servers(configuration.servers.size());
        for (size_t i = 0; i < configuration.servers.size(); ++i)
        {
            servers[i] = configuration.servers[i].c_str();
        }
        natsOptions_SetServers(options.get(), servers.data(), static_cast<int>(configuration.servers.size()));
    }

    static constexpr int infinite_reconnect_count = -1;
    natsOptions_SetMaxReconnect(options.get(), infinite_reconnect_count);

    // On connections with significant traffic, the client will often figure out there is a problem between PINGS,
    // and as a result the default ping interval is typically on the order of minutes.
    // To close an unresponsive connection after 3m, set the ping interval to 60'000 milliseconds and the maximum pings outstanding to 3
    natsOptions_SetPingInterval(options.get(), 60'000);
    natsOptions_SetMaxPingsOut(options.get(), 3);

    natsOptions_SetReconnectWait(options.get(), configuration.reconnect_wait);
    natsOptions_SetDisconnectedCB(options.get(), disconnectedCallback, this);
    natsOptions_SetReconnectedCB(options.get(), reconnectedCallback, this);
}
NATSConnection::~NATSConnection()
{
    disconnect();
}


String NATSConnection::connectionInfoForLog() const
{
    if (!configuration.url.empty())
    {
        return "url : " + configuration.url;
    }
    return "cluster: " + boost::algorithm::join(configuration.servers, ", ");
}

bool NATSConnection::isConnected()
{
    std::lock_guard lock(mutex);
    return isConnectedImpl(lock);
}

bool NATSConnection::isDisconnected()
{
    std::lock_guard lock(mutex);
    return isDisconnectedImpl(lock);
}

bool NATSConnection::isClosed()
{
    std::lock_guard lock(mutex);
    return isClosedImpl(lock);
}

bool NATSConnection::connect()
{
    std::lock_guard lock(mutex);
    connectImpl(lock);
    return isConnectedImpl(lock);
}

void NATSConnection::disconnect()
{
    std::lock_guard lock(mutex);
    disconnectImpl(lock);
}

bool NATSConnection::isConnectedImpl(const Lock &) const
{
    return connection && (natsConnection_Status(connection.get()) == NATS_CONN_STATUS_CONNECTED || natsConnection_IsDraining(connection.get()));
}

bool NATSConnection::isDisconnectedImpl(const Lock &) const
{
    return !connection || (natsConnection_Status(connection.get()) == NATS_CONN_STATUS_DISCONNECTED || natsConnection_IsClosed(connection.get()));
}

bool NATSConnection::isClosedImpl(const Lock &) const
{
    return !connection || natsConnection_IsClosed(connection.get());
}


void NATSConnection::connectImpl(const Lock &)
{
    natsConnection * new_connection = nullptr;
    natsStatus status = natsConnection_Connect(&new_connection, options.get());
    if (status != NATS_OK)
    {
        LOG_DEBUG(log, "New connection to {} failed. Nats status text: {}. Last error message: {}",
                  connectionInfoForLog(), natsStatus_GetText(status), nats_GetLastError(nullptr));
        return;
    }
    connection.reset(new_connection);

    LOG_DEBUG(log, "New connection {} is connected to {}", static_cast<void*>(this), connectionInfoForLog());
}

void NATSConnection::disconnectImpl(const Lock & connection_lock)
{
    if (isDisconnectedImpl(connection_lock))
        return;

    natsConnection_Close(connection.get());
}

void NATSConnection::reconnectedCallback(natsConnection *, void * connection)
{
    LOG_DEBUG(callback_logger, "Connection {} got reconnected to NATS server", static_cast<void*>(connection));
}

void NATSConnection::disconnectedCallback(natsConnection *, void * connection)
{
    LOG_DEBUG(callback_logger, "Connection {} got disconnected from NATS server", connection);
}

}
