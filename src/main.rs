use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use hickory_proto::{
    op::{Message, ResponseCode},
    serialize::binary::BinEncodable,
    xfer::Protocol,
};
use hickory_resolver::{
    Resolver,
    config::{NameServerConfig, NameServerConfigGroup, ResolverConfig},
    name_server::TokioConnectionProvider,
};
use moka::future::Cache;
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::RootCertStore;
use tokio::{net::UdpSocket, sync::RwLock, time::timeout};
use tracing::{error, info, warn};

const BUFFER_SIZE: usize = 4096;
const CACHE_MAX_CAPACITY: u64 = 10000;
const CACHE_TTL_SECS: u64 = 300; // 5 minutes

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create DNS proxy
    let proxy = DnsProxy::new().await?;
    notify_systemd_ready();
    proxy.run().await;
    Ok(())
}

fn notify_systemd_ready() {
    if let Err(err) = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        warn!("Failed to notify systemd readiness: {}", err);
    }
}

struct DnsProxy {
    manager: Arc<ConnectionManager>,
    cache: Arc<Cache<Vec<u8>, Vec<u8>>>,
    socket: Arc<UdpSocket>,
    debug_mode: bool,
    timeout_count: Arc<AtomicUsize>,
}

impl DnsProxy {
    async fn new() -> Result<Self> {
        // Get configuration from environment variables
        let upstream_server =
            std::env::var("UPSTREAM_SERVER").unwrap_or_else(|_| "dns.adguard-dns.com".to_string());
        let upstream_port: u16 = std::env::var("UPSTREAM_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(853);
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.53:53".to_string());
        let debug_mode = std::env::var("DEBUG").map(|v| v == "1").unwrap_or(false);

        // Create UDP socket for receiving DNS queries
        info!("Listening for DNS queries on {}", &bind_addr);
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("Failed to bind UDP socket")?;

        // Create connection manager
        let mut manager = ConnectionManager::new(upstream_server, upstream_port)?;
        if let Ok(ips_string) = std::env::var("UPSTREAM_IP") {
            let ips: Vec<IpAddr> = ips_string
                .split(',')
                .map(|raw_str| {
                    let ip_str = raw_str.trim();
                    ip_str
                        .parse()
                        .context(format!("can not parse IP address {}", ip_str))
                        .unwrap()
                })
                .collect();
            manager = manager.with_server_ip(ips);
        }
        if let Ok(bootstrap_dns) = std::env::var("BOOTSTRAP_DNS") {
            let addr: SocketAddr = bootstrap_dns
                .parse()
                .context("Invalid BOOTSTRAP_DNS format")?;
            manager = manager.with_bootstrap_dns(addr);
        }
        info!("Connection manager initialized");

        // Create DNS response cache
        let cache: Cache<Vec<u8>, Vec<u8>> = Cache::builder()
            .max_capacity(CACHE_MAX_CAPACITY)
            .time_to_live(Duration::from_secs(CACHE_TTL_SECS))
            .build();

        info!(
            "Cache initialized: max {} entries, TTL {}s",
            CACHE_MAX_CAPACITY, CACHE_TTL_SECS
        );
        Ok(Self {
            manager: Arc::new(manager),
            cache: Arc::new(cache),
            socket: Arc::new(socket),
            debug_mode,
            timeout_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    async fn run(self) {
        let proxy = Arc::new(self);
        let mut buf = vec![0u8; BUFFER_SIZE];
        loop {
            match proxy.socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    let query_data = buf[..len].to_vec();
                    let proxy = Arc::clone(&proxy);

                    tokio::spawn(async move {
                        proxy.handle_query(query_data, src_addr).await;
                    });
                }
                Err(e) => {
                    error!("Error receiving UDP packet: {}", e);
                }
            }
        }
    }

    async fn ensure_connection_background(&self) {
        if self.manager.is_connecting() || self.manager.is_connected().await {
            return;
        }

        let manager = self.manager.clone(); // Clone the Arc
        tokio::spawn(async move {
            let _ = manager.connect(false).await;
        });
    }

    async fn handle_query(&self, query_data: Vec<u8>, src_addr: SocketAddr) {
        if self.debug_mode {
            // Parse query for debugging
            if let Ok(query) = Message::from_vec(&query_data) {
                info!("Received query from {}: {:?}", src_addr, query.queries());
            } else {
                error!("Received invalid DNS query from {}", src_addr);
                send_servfail_raw(&query_data, &self.socket, src_addr).await;
                return;
            }
        }

        // Extract query ID to restore later
        let query_id = if query_data.len() >= 2 {
            [query_data[0], query_data[1]]
        } else {
            [0, 0]
        };

        // Create cache key from question section (skip 12-byte header)
        let cache_key = if query_data.len() > 12 {
            query_data[12..].to_vec()
        } else {
            query_data.clone()
        };

        // Check cache
        if let Some(mut cached_response) = self.cache.get(&cache_key).await {
            // Replace response ID with query ID
            if cached_response.len() >= 2 {
                cached_response[0] = query_id[0];
                cached_response[1] = query_id[1];
            }

            if self.debug_mode {
                info!("Cache HIT for query from {}", src_addr);
            }

            if let Err(e) = self.socket.send_to(&cached_response, src_addr).await {
                error!("Failed to send cached response to client: {}", e);
            }
            return;
        }

        if self.debug_mode {
            info!("Cache MISS for query from {}", src_addr);
        }

        self.ensure_connection_background().await;

        // Start timer for processing duration
        let start_time = Instant::now();

        // Process query and send response (or SERVFAIL on error)
        match timeout(Duration::from_secs(5), self.process_query(&query_data)).await {
            Ok(Ok(response_buf)) => {
                self.timeout_count.store(0, Ordering::Relaxed);
                if self.debug_mode {
                    let duration = start_time.elapsed();
                    // Validate and log response in debug mode
                    match Message::from_vec(&response_buf) {
                        Ok(response) => {
                            info!(
                                "Sending valid response to {} (took {:?}): {:?}",
                                src_addr,
                                duration,
                                response.answers(),
                            );
                        }
                        Err(e) => {
                            error!("Received invalid DNS response from upstream: {}", e);
                            send_servfail_raw(&query_data, &self.socket, src_addr).await;
                            return;
                        }
                    }
                }

                // Cache the response (with original query ID)
                self.cache.insert(cache_key, response_buf.clone()).await;

                // Send response to client
                if let Err(e) = self.socket.send_to(&response_buf, src_addr).await {
                    error!("Failed to send response to client: {}", e);
                }
            }
            Ok(Err(e)) => {
                self.timeout_count.store(0, Ordering::Relaxed);
                error!("Error processing query: {}", e);
                send_servfail_raw(&query_data, &self.socket, src_addr).await;
            }
            Err(_) => {
                warn!("Query timeout after 5 seconds for {}", src_addr);
                send_servfail_raw(&query_data, &self.socket, src_addr).await;

                let timeout_count = self.timeout_count.fetch_add(1, Ordering::Relaxed) + 1;
                if timeout_count > 5 {
                    self.timeout_count.store(0, Ordering::Relaxed);
                    warn!(
                        "Timeout circuit breaker tripped after {} timeouts; reconnecting",
                        timeout_count
                    );
                    self.manager.reconnect();
                }
            }
        }
    }

    async fn process_query(&self, query_data: &[u8]) -> Result<Vec<u8>> {
        // Get connection (will reconnect if needed)
        let connection = self.manager.get_connection().await?;

        // Open a bidirectional stream for the DNS query
        let (mut send, recv) = connection
            .open_bi()
            .await
            .context("Failed to open bidirectional stream")?;

        // Wrap recv in a guard that ensures stop() is called on drop
        let mut recv = RecvStreamGuard::new(recv);

        // Send DNS query over QUIC (DoQ uses 2-byte length prefix)
        let len_prefix = (query_data.len() as u16).to_be_bytes();

        send.write_all(&len_prefix)
            .await
            .context("Failed to write length prefix")?;
        send.write_all(query_data)
            .await
            .context("Failed to write DNS query")?;
        send.finish().context("Failed to finish sending")?;

        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf)
            .await
            .context("Failed to read response length")?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Read response from upstream DoQ server
        let mut response_buf = vec![0u8; response_len];
        recv.read_exact(&mut response_buf)
            .await
            .context("Failed to read DNS response")?;

        Ok(response_buf)
    }
}

struct RecvStreamGuard {
    inner: Option<quinn::RecvStream>,
}

impl RecvStreamGuard {
    fn new(recv: quinn::RecvStream) -> Self {
        Self { inner: Some(recv) }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        if let Some(ref mut recv) = self.inner {
            recv.read_exact(buf)
                .await
                .context("Failed to read from recv stream")
        } else {
            Err(anyhow::anyhow!("recv stream already consumed"))
        }
    }
}

impl Drop for RecvStreamGuard {
    fn drop(&mut self) {
        if let Some(mut recv) = self.inner.take() {
            let _ = recv.stop(0u32.into());
        }
    }
}

struct ConnectionManager {
    endpoint: Endpoint,
    server_name: String,
    server_ip: Option<Vec<IpAddr>>,
    server_port: u16,
    bootstrap_dns: Option<SocketAddr>,
    connection: Arc<RwLock<Option<Connection>>>,
    force_reconnect: AtomicBool,
    connecting: AtomicBool,
}

impl ConnectionManager {
    fn new(server_name: String, server_port: u16) -> Result<Self> {
        // Setup QUIC client configuration
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        client_crypto.alpn_protocols = vec![b"doq".to_vec()];

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        transport.max_idle_timeout(Some(Duration::from_hours(1).try_into().unwrap()));

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
        ));
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            server_name,
            server_ip: None,
            server_port,
            bootstrap_dns: None,
            connection: Arc::new(RwLock::new(None)),
            force_reconnect: AtomicBool::new(false),
            connecting: AtomicBool::new(false),
        })
    }

    fn with_server_ip(mut self, ip: Vec<IpAddr>) -> Self {
        self.server_ip = Some(ip);
        self
    }

    fn with_bootstrap_dns(mut self, addr: SocketAddr) -> Self {
        self.bootstrap_dns = Some(addr);
        self
    }

    fn reconnect(&self) {
        self.force_reconnect.store(true, Ordering::Relaxed);
    }

    async fn is_connected(&self) -> bool {
        let conn_guard = self.connection.read().await;
        if let Some(conn) = conn_guard.as_ref() {
            conn.close_reason().is_none()
        } else {
            false
        }
    }

    fn is_connecting(&self) -> bool {
        self.connecting.load(Ordering::Relaxed)
    }

    async fn get_connection(&self) -> Result<Connection> {
        if self.force_reconnect.swap(false, Ordering::Relaxed) {
            // Forced reconnect requested
            return self.connect(true).await;
        }
        // Try to use existing connection

        let conn_guard = self.connection.read().await;
        if let Some(conn) = conn_guard.as_ref() {
            if let Some(reason) = conn.close_reason() {
                warn!(
                    "Existing connection is closed, will reconnect. reason: {:?}",
                    reason
                );
            } else {
                return Ok(conn.clone());
            }
        }

        return self.connect(false).await;
    }

    async fn connect(&self, force: bool) -> Result<Connection> {
        self.connecting.store(true, Ordering::Relaxed);

        // Need to establish new connection
        let mut conn_guard = self.connection.write().await;

        // Double-check in case another task already reconnected
        if !force
            && let Some(conn) = conn_guard.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }

        let remote_ips = if let Some(ip) = self.server_ip.clone() {
            ip
        } else {
            resolve_upstream_addr(&self.server_name, self.bootstrap_dns).await?
        };

        for remote_ip in remote_ips.clone() {
            let remote_addr = SocketAddr::new(remote_ip, self.server_port);

            match timeout(Duration::from_secs(5),  self.connect_to(remote_addr)).await {
                Ok(Ok(connection)) => {
                    info!("Connected to DoQ server at {}", remote_addr);
                    *conn_guard = Some(connection.clone());
                    self.connecting.store(false, Ordering::Relaxed);
                    return Ok(connection);
                }
                Ok(Err(e)) => {
                    warn!("Failed to connect to {}: {}", remote_addr, e);
                }
                Err(_) => {
                    warn!("Connection attempt to {} timed out", remote_addr);
                }
            }
        }

        self.connecting.store(false, Ordering::Relaxed);
        Err(anyhow::anyhow!(
            "Failed to connect to any resolved IP addresses: {:?}",
            remote_ips
        ))
    }

    async fn connect_to(&self, remote_addr: SocketAddr) -> Result<Connection> {
        info!("Establishing new QUIC connection to {}", remote_addr);
        let connection = self
            .endpoint
            .connect(remote_addr, &self.server_name)
            .context("Failed to initiate QUIC connection")?
            .await
            .context("Failed to establish QUIC connection")?;
        info!(
            "Successfully connected to upstream DoQ server at {}",
            remote_addr
        );
        Ok(connection)
    }
}

async fn resolve_upstream_addr(
    host: &str,
    bootstrap_dns: Option<SocketAddr>,
) -> Result<Vec<IpAddr>> {
    let server = bootstrap_dns.unwrap_or_else(|| "1.1.1.1:53".parse().unwrap());

    let mut ns = NameServerConfigGroup::with_capacity(1);
    ns.push(NameServerConfig::new(server, Protocol::Udp));

    let resolver = Resolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], ns),
        TokioConnectionProvider::default(),
    )
    .build();

    let response = resolver
        .lookup_ip(host)
        .await
        .context("can not resolve upstream ip")?;

    let ips: Vec<IpAddr> = response.iter().collect();
    if ips.is_empty() {
        Err(anyhow::anyhow!(
            "No IP addresses found for {} with resolver {:?}",
            host,
            server
        ))
    } else {
        Ok(ips)
    }
}

async fn send_servfail(query: &Message, socket: &UdpSocket, src_addr: SocketAddr) {
    // Create SERVFAIL response
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(hickory_proto::op::MessageType::Response);
    response.set_op_code(query.op_code());
    response.set_response_code(ResponseCode::ServFail);

    // Copy questions from query
    for question in query.queries() {
        response.add_query(question.clone());
    }

    match response.to_bytes() {
        Ok(response_bytes) => {
            warn!("Sending SERVFAIL response to {}", src_addr);
            if let Err(e) = socket.send_to(&response_bytes, src_addr).await {
                error!("Failed to send SERVFAIL response: {}", e);
            }
        }
        Err(e) => {
            error!("Failed to encode SERVFAIL response: {}", e);
        }
    }
}

async fn send_servfail_raw(query_data: &[u8], socket: &UdpSocket, src_addr: SocketAddr) {
    // Try to parse query to create proper SERVFAIL
    if let Ok(query) = Message::from_vec(query_data) {
        send_servfail(&query, socket, src_addr).await;
    } else {
        warn!(
            "Failed to parse query for SERVFAIL, cannot respond to {}",
            src_addr
        );
    }
}
