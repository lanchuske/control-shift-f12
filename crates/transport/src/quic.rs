#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 16]);

pub fn canonical_initiator(local: NodeId, remote: NodeId) -> NodeId {
    local.min(remote)
}

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport unavailable")]
    Unavailable,
    #[error("peer identity rejected")]
    IdentityRejected,
    #[error("incompatible protocol")]
    VersionMismatch,
    #[error("connection timed out")]
    Timeout,
    #[error("invalid transport options")]
    InvalidOptions,
    #[error("reconnect exhausted after {attempts} attempts")]
    ReconnectExhausted { attempts: u32 },
}

/// Task 4 supplies a verifier that binds the claimed ID to mutually pinned
/// TLS certificate identity. A missing verifier leaves a session pending.
pub trait PeerIdentityVerifier: Send + Sync {
    fn verify(&self, connection: &quinn::Connection, claimed: NodeId)
    -> Result<(), TransportError>;
}

#[derive(Clone)]
pub struct EndpointOptions {
    pub version: u16,
    pub handshake_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub idle_timeout: Duration,
    pub verifier: Option<Arc<dyn PeerIdentityVerifier>>,
}
impl Default for EndpointOptions {
    fn default() -> Self {
        Self {
            version: 1,
            handshake_timeout: Duration::from_secs(5),
            heartbeat_interval: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(8),
            verifier: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionTrust {
    PendingIdentity,
    Authenticated,
}

#[derive(Clone, Debug)]
pub struct PeerSession {
    peer: NodeId,
    initiator: NodeId,
    dial_nonce: u64,
    trust: SessionTrust,
    connection: quinn::Connection,
}
impl PeerSession {
    pub fn peer(&self) -> NodeId {
        self.peer
    }
    pub fn initiator(&self) -> NodeId {
        self.initiator
    }
    pub fn dial_nonce(&self) -> u64 {
        self.dial_nonce
    }
    pub fn trust(&self) -> SessionTrust {
        self.trust
    }
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }
    pub fn authenticated_connection(&self) -> Option<&quinn::Connection> {
        (self.trust == SessionTrust::Authenticated).then_some(&self.connection)
    }
}

#[derive(Clone, Debug)]
pub struct ReconnectPolicy {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub max_attempts: u32,
}
impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(5),
            max_attempts: 5,
        }
    }
}
impl ReconnectPolicy {
    pub fn delays(&self) -> Result<Vec<Duration>, TransportError> {
        if self.max_attempts == 0
            || self.max_attempts > 32
            || self.initial_delay.is_zero()
            || self.initial_delay > self.max_delay
            || self.max_delay > Duration::from_secs(60)
        {
            return Err(TransportError::InvalidOptions);
        }
        let mut delay = self.initial_delay;
        let mut delays = Vec::new();
        for _ in 1..self.max_attempts {
            delays.push(delay);
            delay = delay.saturating_mul(2).min(self.max_delay);
        }
        Ok(delays)
    }
}

struct EndpointState {
    id: NodeId,
    options: EndpointOptions,
    sessions: Mutex<BTreeMap<NodeId, PeerSession>>,
    nonce: AtomicU64,
}

/// One UDP socket accepts and initiates QUIC. No implicit trust store, no
/// insecure certificate verifier, and no production TLS configuration here.
pub struct PeerEndpoint {
    endpoint: quinn::Endpoint,
    state: Arc<EndpointState>,
    accept_task: tokio::task::JoinHandle<()>,
}
impl PeerEndpoint {
    pub fn bind(
        address: SocketAddr,
        id: NodeId,
        mut server: quinn::ServerConfig,
        mut client: quinn::ClientConfig,
        options: EndpointOptions,
    ) -> Result<Self, TransportError> {
        if options.handshake_timeout.is_zero()
            || options.heartbeat_interval.is_zero()
            || options.heartbeat_interval >= options.idle_timeout
        {
            return Err(TransportError::InvalidOptions);
        }
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(options.heartbeat_interval));
        transport.max_idle_timeout(Some(
            options
                .idle_timeout
                .try_into()
                .map_err(|_| TransportError::InvalidOptions)?,
        ));
        transport.max_concurrent_bidi_streams(8u32.into());
        transport.max_concurrent_uni_streams(0u32.into());
        let transport = Arc::new(transport);
        server.transport_config(transport.clone());
        client.transport_config(transport);
        let mut endpoint =
            quinn::Endpoint::server(server, address).map_err(|_| TransportError::Unavailable)?;
        endpoint.set_default_client_config(client);
        let state = Arc::new(EndpointState {
            id,
            options,
            sessions: Mutex::new(BTreeMap::new()),
            nonce: AtomicU64::new(1),
        });
        let incoming_endpoint = endpoint.clone();
        let incoming_state = state.clone();
        let slots = Arc::new(tokio::sync::Semaphore::new(32));
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = incoming_endpoint.accept().await {
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let state = incoming_state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(state.options.handshake_timeout, async {
                        let connection = incoming.await.map_err(|_| TransportError::Unavailable)?;
                        negotiate(state, connection, false, None, 0).await
                    })
                    .await;
                });
            }
        });
        Ok(Self {
            endpoint,
            state,
            accept_task,
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint
            .local_addr()
            .expect("bound endpoint retains its UDP socket")
    }
    pub async fn dial(
        &self,
        address: SocketAddr,
        server_name: &str,
        expected: Option<NodeId>,
    ) -> Result<PeerSession, TransportError> {
        let nonce = self.state.nonce.fetch_add(1, Ordering::Relaxed);
        let connection = tokio::time::timeout(
            self.state.options.handshake_timeout,
            self.endpoint
                .connect(address, server_name)
                .map_err(|_| TransportError::Unavailable)?,
        )
        .await
        .map_err(|_| TransportError::Timeout)?
        .map_err(classify_connection_error)?;
        let result = tokio::time::timeout(
            self.state.options.handshake_timeout,
            negotiate(
                self.state.clone(),
                connection.clone(),
                true,
                expected,
                nonce,
            ),
        )
        .await
        .map_err(|_| TransportError::Timeout)
        .and_then(|result| result);
        if result.is_err() {
            connection.close(1u32.into(), b"session rejected");
        }
        result
    }
    pub fn sessions(&self) -> Vec<PeerSession> {
        let mut sessions = self.state.sessions.lock().unwrap();
        sessions.retain(|_, session| !session.is_closed());
        sessions.values().cloned().collect()
    }
    /// Retry only transient reachability errors. Trust/version failures never
    /// trigger another attempt. The caller decides when a disconnect warrants
    /// reconnection; dropping this future cancels the retry loop.
    pub async fn reconnect(
        &self,
        address: SocketAddr,
        server_name: &str,
        expected: Option<NodeId>,
        policy: &ReconnectPolicy,
    ) -> Result<PeerSession, TransportError> {
        let delays = policy.delays()?;
        for attempt in 0..policy.max_attempts {
            match self.dial(address, server_name, expected).await {
                Ok(session) => return Ok(session),
                Err(TransportError::Unavailable | TransportError::Timeout) => {}
                Err(error) => return Err(error),
            }
            if let Some(delay) = delays.get(attempt as usize) {
                tokio::time::sleep(*delay).await;
            }
        }
        Err(TransportError::ReconnectExhausted {
            attempts: policy.max_attempts,
        })
    }
}
impl Drop for PeerEndpoint {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"endpoint stopped");
        self.accept_task.abort();
    }
}

async fn negotiate(
    state: Arc<EndpointState>,
    connection: quinn::Connection,
    outbound: bool,
    expected: Option<NodeId>,
    nonce: u64,
) -> Result<PeerSession, TransportError> {
    let result = negotiate_inner(&state, &connection, outbound, expected, nonce).await;
    if let Err(error) = &result {
        let code: u32 = if matches!(error, TransportError::VersionMismatch) {
            2
        } else {
            1
        };
        connection.close(code.into(), b"session rejected");
    }
    result
}

async fn negotiate_inner(
    state: &Arc<EndpointState>,
    connection: &quinn::Connection,
    outbound: bool,
    expected: Option<NodeId>,
    nonce: u64,
) -> Result<PeerSession, TransportError> {
    let (mut send, mut recv) = if outbound {
        connection.open_bi().await
    } else {
        connection.accept_bi().await
    }
    .map_err(|_| TransportError::Unavailable)?;
    let mut hello = [0u8; 26];
    hello[..2].copy_from_slice(&state.options.version.to_be_bytes());
    hello[2..18].copy_from_slice(&state.id.0);
    hello[18..].copy_from_slice(&nonce.to_be_bytes());
    send.write_all(&hello)
        .await
        .map_err(|_| TransportError::Unavailable)?;
    let mut remote = [0u8; 26];
    recv.read_exact(&mut remote)
        .await
        .map_err(|_| connection_error(connection))?;
    if u16::from_be_bytes(remote[..2].try_into().unwrap()) != state.options.version {
        return Err(TransportError::VersionMismatch);
    }
    let peer = NodeId(remote[2..18].try_into().unwrap());
    if peer == state.id || expected.is_some_and(|id| id != peer) {
        return Err(TransportError::IdentityRejected);
    }
    let trust = if let Some(verifier) = &state.options.verifier {
        if connection.peer_identity().is_none() {
            return Err(TransportError::IdentityRejected);
        }
        verifier.verify(connection, peer)?;
        SessionTrust::Authenticated
    } else {
        SessionTrust::PendingIdentity
    };
    // Neither endpoint installs a session until the other has also validated
    // the hello. This acknowledgement is negotiation, not proof of identity.
    send.write_all(&[1])
        .await
        .map_err(|_| TransportError::Unavailable)?;
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack)
        .await
        .map_err(|_| connection_error(connection))?;
    if ack != [1] {
        return Err(TransportError::IdentityRejected);
    }
    send.finish().map_err(|_| TransportError::Unavailable)?;
    let initiator = if outbound { state.id } else { peer };
    let dial_nonce = if outbound {
        nonce
    } else {
        u64::from_be_bytes(remote[18..].try_into().unwrap())
    };
    let candidate = PeerSession {
        peer,
        initiator,
        dial_nonce,
        trust,
        connection: connection.clone(),
    };
    let rank = |session: &PeerSession| {
        (
            session.initiator != canonical_initiator(state.id, peer),
            session.dial_nonce,
        )
    };
    let mut sessions = state.sessions.lock().unwrap();
    if let Some(existing) = sessions.get(&peer).filter(|session| !session.is_closed()) {
        if rank(existing) <= rank(&candidate) {
            connection.close(0u32.into(), b"duplicate session");
            return Ok(existing.clone());
        }
        existing
            .connection
            .close(0u32.into(), b"canonical session elected");
    }
    sessions.insert(peer, candidate.clone());
    Ok(candidate)
}

fn connection_error(connection: &quinn::Connection) -> TransportError {
    connection
        .close_reason()
        .map(classify_connection_error)
        .unwrap_or(TransportError::Unavailable)
}

fn classify_connection_error(error: quinn::ConnectionError) -> TransportError {
    match error {
        quinn::ConnectionError::ApplicationClosed(error) if error.error_code == 2u32.into() => {
            TransportError::VersionMismatch
        }
        quinn::ConnectionError::ApplicationClosed(error) if error.error_code == 1u32.into() => {
            TransportError::IdentityRejected
        }
        quinn::ConnectionError::TransportError(error)
            if (0x100..0x200).contains(&u64::from(error.code)) =>
        {
            TransportError::IdentityRejected
        }
        _ => TransportError::Unavailable,
    }
}
