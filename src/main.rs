use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    serialize::binary::BinEncodable,
};
use hickory_resolver::{
    Resolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use moka::sync::Cache;
use once_cell::sync::OnceCell;
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::client::WebPkiServerVerifier;
use rustls_native_certs::load_native_certs;
use std::{
    hint::cold_path,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
    vec,
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, RwLock},
    time::timeout,
};
use tracing::{debug, error, info, warn};

const BUFFER_SIZE: usize = 4096;
const CACHE_MAX_CAPACITY: u64 = 10000;

static RESOLVER: OnceCell<Resolver<TokioRuntimeProvider>> = OnceCell::new();

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create DNS proxy
    let proxy = DnsProxy::new().await?;
    if let Err(err) = sd_notify::notify(&[sd_notify::NotifyState::Ready]) {
        warn!("Failed to notify systemd readiness: {}", err);
    }
    proxy.run().await
}

struct DnsProxy {
    manager: Arc<ConnectionManager>,
    cache: Arc<Cache<Bytes, Bytes>>,
    socket: Arc<UdpSocket>,
    debug_mode: bool,
    timeout_count: Arc<AtomicUsize>,
    force_reconnect: Arc<AtomicBool>,
    connection_epoch: Arc<AtomicUsize>,
    in_flight: Arc<AtomicUsize>,
    in_flight_drained: Arc<Notify>,
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

        // Create connection manager
        let mut manager = ConnectionManager::new(upstream_server, upstream_port)?;
        if let Ok(ips_string) = std::env::var("UPSTREAM_IP") {
            let addrs: Vec<SocketAddr> = ips_string
                .split(',')
                .map(|raw_str| {
                    let ip_str = raw_str.trim();
                    SocketAddr::new(
                        ip_str
                            .parse()
                            .context(format!("can not parse IP address {}", ip_str))
                            .unwrap(),
                        upstream_port,
                    )
                })
                .collect();
            manager.with_server_addrs(addrs);
        }
        if let Ok(bootstrap_dns) = std::env::var("BOOTSTRAP_DNS") {
            let addr: SocketAddr = bootstrap_dns
                .parse()
                .context("Invalid BOOTSTRAP_DNS format")?;
            manager.with_bootstrap_dns(addr);
        }
        info!("Connection manager initialized");

        let ttl = std::env::var("CACHE_TTL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);

        // Create DNS response cache
        let cache: Cache<Bytes, Bytes> = Cache::builder()
            .max_capacity(CACHE_MAX_CAPACITY)
            .time_to_live(Duration::from_secs(ttl))
            .build();

        info!(
            "Cache initialized: max {} entries, TTL {}s",
            CACHE_MAX_CAPACITY, ttl
        );

        // Create UDP socket for receiving DNS queries
        info!("Listening for DNS queries on {}", &bind_addr);
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("Failed to bind UDP socket")?;

        Ok(Self {
            manager: Arc::new(manager),
            cache: Arc::new(cache),
            socket: Arc::new(socket),
            debug_mode,
            timeout_count: Arc::new(AtomicUsize::new(0)),
            force_reconnect: Arc::new(AtomicBool::new(false)),
            connection_epoch: Arc::new(AtomicUsize::new(0)),
            in_flight: Arc::new(AtomicUsize::new(0)),
            in_flight_drained: Arc::new(Notify::new()),
        })
    }

    async fn run(self) -> Result<()> {
        let proxy = Arc::new(self);
        let mut buf = [0u8; BUFFER_SIZE];
        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                signal = &mut shutdown => {
                    signal?;
                    info!("Shutdown requested; no longer accepting DNS queries");
                    if let Err(err) = sd_notify::notify(&[sd_notify::NotifyState::Stopping]) {
                        warn!("Failed to notify systemd shutdown: {}", err);
                    }
                    break;
                }
                result = proxy.socket.recv_from(&mut buf) => match result {
                    Ok((len, src_addr)) => {
                        if len <= 12 {
                            cold_path();
                            error!("Received DNS query too short from {}", src_addr);
                            continue;
                        }

                        // Keep the common localhost cache-hit path in the receive
                        // loop: no task allocation and no await before the next recv.
                        if is_cacheable_query(&buf[..len]) {
                            if proxy.handle_from_cache(&buf[..len], src_addr) {
                                continue;
                            }
                        } else {
                            cold_path();
                            debug!("Received non-cacheable query from {}", src_addr);
                        }

                        let in_flight = proxy.create_in_flight();
                        let query_data = Bytes::copy_from_slice(&buf[..len]);
                        let proxy = Arc::clone(&proxy);
                        tokio::spawn(async move {
                            let _in_flight = in_flight;
                            proxy.handle_query(query_data, src_addr).await;
                        });
                    }
                    Err(e) => {
                        cold_path();
                        error!("Error receiving UDP packet: {}", e);
                    }
                },
            }
        }

        // Query handlers have their own five-second upstream timeout. Let them finish
        // so clients receive either their response or SERVFAIL before closing QUIC.
        match timeout(Duration::from_secs(5), proxy.wait_for_in_flight()).await {
            Ok(()) => info!("All in-flight DNS queries completed"),
            Err(_) => warn!("Shutdown grace period elapsed; closing upstream connection"),
        }

        proxy.manager.shutdown();
        info!("DNS proxy stopped");
        Ok(())
    }

    #[inline(always)]
    fn create_in_flight(&self) -> InFlightGuard {
        InFlightGuard::new(
            Arc::clone(&self.in_flight),
            Arc::clone(&self.in_flight_drained),
        )
    }

    async fn ensure_connection_background(&self) {
        let force_reconnect = self.force_reconnect.swap(false, Ordering::Relaxed);
        if !force_reconnect && (self.manager.is_connecting() || self.manager.is_connected().await) {
            return;
        }

        let manager = self.manager.clone();
        let timeout_count = self.timeout_count.clone();
        let connection_epoch = self.connection_epoch.clone();
        tokio::spawn(async move {
            if manager.connect(force_reconnect).await.is_ok() {
                // Bump epoch so stale timeout handlers from the old connection
                // don't re-trip the circuit breaker on the new connection.
                connection_epoch.fetch_add(1, Ordering::Relaxed);
                timeout_count.store(0, Ordering::Relaxed);
            }
        });
    }

    async fn wait_for_in_flight(&self) {
        while self.in_flight.load(Ordering::Acquire) != 0 {
            self.in_flight_drained.notified().await;
        }
    }

    fn handle_from_cache(&self, query_data: &[u8], src_addr: SocketAddr) -> bool {
        let cached_response = match self.cache.get(&query_data[12..]) {
            Some(response) => response,
            None => return false,
        };

        if cached_response.len() < 2 {
            cold_path();
            error!("Ignoring cached DNS response shorter than its transaction ID");
            return false;
        }
        let mut response = BytesMut::from(cached_response.as_ref());
        drop(cached_response);

        response[..2].copy_from_slice(&query_data[..2]);
        match self.socket.try_send_to(&response, src_addr) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                warn!("UDP socket send buffer full; spawning task to send cached response to {}", src_addr);
                let in_flight = self.create_in_flight();
                let socket = Arc::clone(&self.socket);
                tokio::spawn(async move {
                    let _in_flight = in_flight;
                    if let Err(e) = socket.send_to(&response, src_addr).await {
                        cold_path();
                        error!("Failed to send cached response to client: {}", e);
                    }
                });
            }
            Err(e) => {
                cold_path();
                error!("Failed to send cached response to client: {}", e);
            }
        }
        true
    }

    async fn handle_query(&self, query_data: Bytes, src_addr: SocketAddr) {
        if self.debug_mode {
            cold_path();
            // Parse query for debugging
            if let Ok(query) = Message::from_vec(&query_data) {
                info!("Received query from {}: {:?}", src_addr, query.queries);
            } else {
                error!("Received invalid DNS query from {}", src_addr);
                send_servfail_raw(&query_data, &self.socket, src_addr).await;
                return;
            }
        }

        // Capture the epoch before submitting the query. If the connection is
        // re-established while this query is in flight, the epoch will increase
        // and this query's timeout won't re-trip the circuit breaker.
        let query_epoch = self.connection_epoch.load(Ordering::Relaxed);
        self.ensure_connection_background().await;

        // Start timer for processing duration
        let start_time = Instant::now();

        // Process query and send response (or SERVFAIL on error)
        match timeout(Duration::from_secs(5), self.process_query(&query_data)).await {
            Ok(Ok(response_buf)) => {
                self.timeout_count.store(0, Ordering::Relaxed);
                if self.debug_mode {
                    cold_path();
                    let duration = start_time.elapsed();
                    // Validate and log response in debug mode
                    match Message::from_vec(&response_buf) {
                        Ok(response) => {
                            info!(
                                "Sending valid response to {} (took {:?}): {:?}",
                                src_addr, duration, response.answers,
                            );
                        }
                        Err(e) => {
                            error!("Received invalid DNS response from upstream: {}", e);
                            send_servfail_raw(&query_data, &self.socket, src_addr).await;
                            return;
                        }
                    }
                }

                // Send response to client
                if let Err(e) = self.socket.send_to(&response_buf, src_addr).await {
                    error!("Failed to send response to client: {}", e);
                }

                // Cache only ordinary recursive queries. Diagnostic and DNSSEC
                // control queries bypass the cache to preserve their semantics.
                if is_cacheable_query(&query_data) {
                    self.cache.insert(query_data.slice(12..), response_buf);
                }
            }
            Ok(Err(e)) => {
                cold_path();
                self.timeout_count.store(0, Ordering::Relaxed);
                error!("Error processing query: {}", e);
                send_servfail_raw(&query_data, &self.socket, src_addr).await;
            }
            Err(_) => {
                warn!("Query timeout after 5 seconds for {}", src_addr);
                send_servfail_raw(&query_data, &self.socket, src_addr).await;

                // Only count timeouts from the current connection epoch.
                // Stale timeouts from queries that were in flight during a previous
                // broken connection must not re-trip the circuit breaker after a
                // successful reconnect has already bumped the epoch.
                let current_epoch = self.connection_epoch.load(Ordering::Relaxed);
                if !self.manager.is_connecting() && current_epoch == query_epoch {
                    let timeout_count = self.timeout_count.fetch_add(1, Ordering::Relaxed) + 1;
                    if timeout_count > 5 {
                        self.timeout_count.store(0, Ordering::Relaxed);
                        warn!(
                            "Timeout circuit breaker tripped after {} timeouts; reconnecting",
                            timeout_count
                        );
                        self.force_reconnect.store(true, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    async fn process_query(&self, query_data: &[u8]) -> Result<Bytes> {
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

        Ok(Bytes::from_owner(response_buf))
    }
}

/// Returns true only for the ordinary recursive DNS queries issued by local
/// browsers and applications: QUERY opcode, RD set, and no other flag bits.
/// Such requests can safely share the raw question-section cache key.
#[inline]
fn is_cacheable_query(query_data: &[u8]) -> bool {
    query_data[2] == 0x01 && query_data[3] == 0x00
}

struct InFlightGuard {
    count: Arc<AtomicUsize>,
    drained: Arc<Notify>,
}

impl InFlightGuard {
    fn new(count: Arc<AtomicUsize>, drained: Arc<Notify>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self { count, drained }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.count.fetch_sub(1, Ordering::Release) == 1 {
            self.drained.notify_one();
        }
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
    server_port: u16,
    bootstrap_dns: Option<SocketAddr>,
    connection: Arc<RwLock<Option<Connection>>>,
    server_addrs: Option<Arc<Vec<SocketAddr>>>,
    connecting: AtomicBool,
}

impl ConnectionManager {
    fn new(server_name: String, server_port: u16) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let mut roots = rustls::RootCertStore::empty();
        for cert in load_native_certs().expect("could not load CA certificates") {
            roots.add(cert).context("failed to add native cert")?;
        }

        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .context("can not create webpki verifier")?;

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_webpki_verifier(verifier)
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
            // server_ip: None,
            server_port,
            bootstrap_dns: None,
            connection: Arc::new(RwLock::new(None)),
            connecting: AtomicBool::new(false),
            server_addrs: None,
        })
    }

    fn with_server_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.server_addrs = Some(Arc::new(addrs));
    }

    fn with_bootstrap_dns(&mut self, addr: SocketAddr) {
        self.bootstrap_dns = Some(addr);
    }

    async fn is_connected(&self) -> bool {
        let conn_guard = self.connection.read().await;
        if let Some(conn) = conn_guard.as_ref() {
            conn.close_reason().is_none()
        } else {
            false
        }
    }

    #[inline(always)]
    fn is_connecting(&self) -> bool {
        self.connecting.load(Ordering::Relaxed)
    }

    async fn get_connection(&self) -> Result<Connection> {
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
        drop(conn_guard);
        return self.connect(false).await;
    }

    fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"server shutting down");
    }

    async fn connect(&self, force: bool) -> Result<Connection> {
        let _connecting = set_flag_guard(&self.connecting);

        // Need to establish new connection
        let mut conn_guard = self.connection.write().await;

        // Double-check in case another task already reconnected
        if !force
            && let Some(conn) = conn_guard.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }

        let remote_addrs = if let Some(addrs) = &self.server_addrs {
            addrs.clone()
        } else {
            self.resolve_upstream_addr().await?
        };

        for &remote_addr in remote_addrs.iter() {
            debug!("Attempting to connect to DoQ server at {}", remote_addr);
            match timeout(Duration::from_secs(3), self.connect_to(remote_addr)).await {
                Ok(Ok(connection)) => {
                    info!("Connected to DoQ server at {}", remote_addr);
                    *conn_guard = Some(connection.clone());
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

        Err(anyhow::anyhow!(
            "Failed to connect to any resolved IP addresses"
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

        // Validate connection is open and functional
        if let Some(close_reason) = connection.close_reason() {
            cold_path();
            return Err(anyhow::anyhow!(
                "Connection closed immediately after establishment: {:?}",
                close_reason
            ));
        }

        {
            // validate connection
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .context("Failed to open test stream on new connection")?;
            send.finish()?;
            recv.stop(0u32.into())?;
        }
        info!(
            "Successfully connected to upstream DoQ server at {}",
            remote_addr
        );
        Ok(connection)
    }

    async fn resolve_upstream_addr(&self) -> Result<Arc<Vec<SocketAddr>>> {
        let server = self
            .bootstrap_dns
            .unwrap_or_else(|| "1.1.1.1:53".parse().unwrap());
        let resolver = RESOLVER.get_or_try_init(move || {
            let mut udp = ConnectionConfig::udp();
            udp.port = server.port();
            let ns = NameServerConfig::new(server.ip(), true, vec![udp]);

            Resolver::builder_with_config(
                ResolverConfig::from_parts(None, vec![], vec![ns]),
                TokioRuntimeProvider::default(),
            )
            .build()
            .context("failed to build bootstrap resolver")
        })?;

        let response = resolver
            .lookup_ip(&self.server_name)
            .await
            .context("can not resolve upstream ip")?;

        let ips: Vec<SocketAddr> = response
            .iter()
            .map(|ip| SocketAddr::new(ip, self.server_port))
            .collect();
        if ips.is_empty() {
            cold_path();
            Err(anyhow::anyhow!(
                "No IP addresses found for {} with resolver {:?}",
                self.server_name,
                server
            ))
        } else {
            Ok(Arc::new(ips))
        }
    }
}

async fn shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).context("Failed to listen for SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("Failed to listen for SIGINT")?;
    tokio::select! {
        _ = terminate.recv() => info!("Received SIGTERM"),
        _ = interrupt.recv() => info!("Received SIGINT"),
    }

    Ok(())
}

async fn send_servfail(query: &Message, socket: &UdpSocket, src_addr: SocketAddr) {
    // Create SERVFAIL response
    let mut response = Message::new(query.id, MessageType::Response, query.op_code);
    response.metadata.response_code = ResponseCode::ServFail;

    // Copy questions from query
    for question in &query.queries {
        response.add_query(question.clone());
    }

    match response.to_bytes() {
        Ok(response_bytes) => {
            debug!("Sending SERVFAIL response to {}", src_addr);
            if let Err(e) = socket.send_to(&response_bytes, src_addr).await {
                warn!("Failed to send SERVFAIL response: {}", e);
            }
        }
        Err(e) => {
            cold_path();
            warn!("Failed to encode SERVFAIL response: {}", e);
        }
    }
}

async fn send_servfail_raw(query_data: &[u8], socket: &UdpSocket, src_addr: SocketAddr) {
    // Try to parse query to create proper SERVFAIL
    if let Ok(query) = Message::from_vec(query_data) {
        send_servfail(&query, socket, src_addr).await;
    } else {
        cold_path();
        warn!(
            "Failed to parse query for SERVFAIL, cannot respond to {}",
            src_addr
        );
    }
}

struct BoolGuard<'a> {
    flag: &'a AtomicBool,
}

fn set_flag_guard<'a>(flag: &'a AtomicBool) -> BoolGuard<'a> {
    flag.store(true, Ordering::Relaxed);
    BoolGuard { flag }
}

impl<'a> Drop for BoolGuard<'a> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::is_cacheable_query;

    #[test]
    fn caches_only_standard_recursive_queries() {
        let mut query = [0_u8; 13];
        query[2] = 0x01; // RD
        assert!(is_cacheable_query(&query));

        query[2] = 0x00; // RD is absent
        assert!(!is_cacheable_query(&query));

        query[2] = 0x09; // QUERY with TC set
        assert!(!is_cacheable_query(&query));

        query[2] = 0x11; // non-QUERY opcode
        assert!(!is_cacheable_query(&query));

        query[2] = 0x01;
        query[3] = 0x10; // CD
        assert!(!is_cacheable_query(&query));
    }
}
