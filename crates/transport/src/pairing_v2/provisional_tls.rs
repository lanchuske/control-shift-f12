//! Strict provisional TLS. Proving possession of a self-signed identity key is
//! NOT user authentication, active trust, finalization or admission.
use super::{
    Invalid,
    operational_binding::{LocalBinding, TransportReplayRegistry},
};
use super::{
    evidence::hash,
    operational_binding::{BindingInput, EXPORTER_LABEL},
    operational_wire::ALPN,
    validate_identity,
};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
mod handshake_io;
#[cfg(test)]
mod tests;
pub(crate) use handshake_io::FrozenPromotionEvidence;
pub use handshake_io::{
    HandshakeCompletePendingAuthority, HandshakeConfig, HandshakeError, VerificationDecision,
    VerificationPrompt,
};
fn utc() -> Result<i64, Invalid> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Invalid)?
            .as_secs(),
    )
    .map_err(|_| Invalid)
}
pub(crate) fn profile(leaf: &[u8], now: i64) -> Result<(), Invalid> {
    let node = hash(leaf)[..16].try_into().map_err(|_| Invalid)?;
    validate_identity(leaf, node, now).map(|_| ())
}
fn tls_error() -> rustls::Error {
    rustls::Error::General("provisional identity rejected".into())
}
#[derive(Debug)]
struct ProfileVerifier(Arc<rustls::crypto::CryptoProvider>);
impl ProfileVerifier {
    fn certificate(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        if !intermediates.is_empty() {
            return Err(tls_error());
        }
        profile(
            leaf.as_ref(),
            i64::try_from(now.as_secs()).map_err(|_| tls_error())?,
        )
        .map_err(|_| tls_error())
    }
    fn signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if signature.scheme != rustls::SignatureScheme::ED25519 {
            return Err(tls_error());
        }
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }
}
impl ServerCertVerifier for ProfileVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.certificate(leaf, intermediates, now)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls_error())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}
impl ClientCertVerifier for ProfileVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.certificate(leaf, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls_error())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}
/// No socket is opened here. Callers must own a bounded consent/listener lease.
/// These configs do not read/write active trust and cannot admit application I/O.
fn configs(
    certificate: Vec<u8>,
    key: PrivateKeyDer<'static>,
) -> Result<(quinn::ServerConfig, StrictClient), Invalid> {
    strict_configs(certificate, key, ALPN, 2, 1)
}

/// Shared strict TLS profile for separately-versioned, sealed control channels.
/// The caller selects only the exact frozen ALPN and QUIC stream cardinality;
/// TLS identity validation, TLS1.3-only, no early data, no resumption and no
/// tickets remain owned here.
pub(crate) fn strict_configs(
    certificate: Vec<u8>,
    key: PrivateKeyDer<'static>,
    alpn: &[u8],
    max_bidi_streams: u32,
    max_uni_streams: u32,
) -> Result<(quinn::ServerConfig, StrictClient), Invalid> {
    if alpn.is_empty() || !alpn.is_ascii() || max_bidi_streams == 0 {
        return Err(Invalid);
    }
    profile(&certificate, utc()?)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(ProfileVerifier(provider.clone()));
    let cert = CertificateDer::from(certificate);
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Invalid)?
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(vec![cert.clone()], key.clone_key())
        .map_err(|_| Invalid)?;
    server.alpn_protocols = vec![alpn.to_vec()];
    server.max_early_data_size = 0;
    server.send_tls13_tickets = 0;
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Invalid)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)
        .map_err(|_| Invalid)?;
    client.alpn_protocols = vec![alpn.to_vec()];
    client.enable_early_data = false;
    client.resumption = rustls::client::Resumption::disabled();
    let mut limits = quinn::TransportConfig::default();
    limits
        // A retains its candidate request half while opening the control stream.
        // The application rejects every extra stream beyond this exact schedule.
        .max_concurrent_bidi_streams(max_bidi_streams.into())
        .max_concurrent_uni_streams(max_uni_streams.into())
        .stream_receive_window(16_399u32.into())
        .receive_window(65_536u32.into())
        .keep_alive_interval(Some(std::time::Duration::from_secs(10)))
        .max_idle_timeout(Some(
            std::time::Duration::from_secs(30)
                .try_into()
                .map_err(|_| Invalid)?,
        ));
    let limits = Arc::new(limits);
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server).map_err(|_| Invalid)?,
    ));
    server.transport_config(limits.clone());
    Ok((
        server,
        StrictClient {
            config: client,
            limits,
        },
    ))
}
pub(crate) struct StrictClient {
    config: rustls::ClientConfig,
    limits: Arc<quinn::TransportConfig>,
}
#[derive(Debug)]
pub(crate) struct ClientAuthEvidence {
    resolver: Arc<dyn rustls::client::ResolvesClientCert>,
    requested: AtomicBool,
}
impl rustls::client::ResolvesClientCert for ClientAuthEvidence {
    fn resolve(
        &self,
        hints: &[&[u8]],
        schemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let key = self.resolver.resolve(hints, schemes);
        if key.is_some() {
            self.requested.store(true, Ordering::Release);
        }
        key
    }
    fn has_certs(&self) -> bool {
        self.resolver.has_certs()
    }
}
impl ClientAuthEvidence {
    pub(crate) fn was_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}
impl StrictClient {
    pub(crate) fn identity(&self) -> Result<Arc<rustls::sign::CertifiedKey>, Invalid> {
        self.config
            .client_auth_cert_resolver
            .resolve(&[], &[rustls::SignatureScheme::ED25519])
            .ok_or(Invalid)
    }
    pub(crate) fn fresh(&self) -> Result<(quinn::ClientConfig, Arc<ClientAuthEvidence>), Invalid> {
        let mut config = self.config.clone();
        let evidence = Arc::new(ClientAuthEvidence {
            resolver: config.client_auth_cert_resolver.clone(),
            requested: AtomicBool::new(false),
        });
        config.client_auth_cert_resolver = evidence.clone();
        let mut client = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(config).map_err(|_| Invalid)?,
        ));
        client.transport_config(self.limits.clone());
        Ok((client, evidence))
    }
}
// One process owner, no public constructors, no registry injection or reset.
// State survives endpoint/consent turnover; only process restart clears it.
struct ProcessOwner {
    replay: TransportReplayRegistry,
    generation: AtomicU64,
}
fn process_owner() -> &'static ProcessOwner {
    static OWNER: OnceLock<ProcessOwner> = OnceLock::new();
    OWNER.get_or_init(|| ProcessOwner {
        replay: TransportReplayRegistry::default(),
        generation: AtomicU64::new(1),
    })
}
impl ProcessOwner {
    fn generation(&self) -> Result<u64, Invalid> {
        self.generation
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| Invalid)
    }
}
/// A consent-scoped endpoint owns strict configs and all connect/accept paths.
/// The app/controller gate remains closed pending independent review; the
/// experimental handshake API can reach only PendingAuthority, never admission.
/// No raw endpoint, connection, config, registry or channel constructor is exposed.
/// Dropping the endpoint revokes all its channels. The process replay owner is
/// never reset by dropping/recreating an endpoint.
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::ProvisionalEndpoint;
/// fn replace(e: &mut ProvisionalEndpoint, raw: quinn::Endpoint) { e.endpoint = raw; }
/// ```
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::configs;
/// ```
pub struct ProvisionalEndpoint {
    endpoint: quinn::Endpoint,
    client: StrictClient,
    owner: &'static ProcessOwner,
    scope: Arc<ConsentScope>,
    #[cfg(test)]
    drop_pause: Option<EndpointDropPause>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsentPhase {
    Active,
    Frozen,
    Revoked,
}
struct ConsentState {
    phase: ConsentPhase,
    revoker: Option<crate::pairing_pending::AdmissionRevoker>,
}
struct ConsentScope(std::sync::Mutex<ConsentState>);
impl ConsentScope {
    fn new() -> Self {
        Self(std::sync::Mutex::new(ConsentState {
            phase: ConsentPhase::Active,
            revoker: None,
        }))
    }
    fn is_active(&self) -> Result<bool, Invalid> {
        Ok(self.0.lock().map_err(|_| Invalid)?.phase == ConsentPhase::Active)
    }
    fn freeze(&self, mut revoker: crate::pairing_pending::AdmissionRevoker) -> Result<(), Invalid> {
        let mut state = self.0.lock().map_err(|_| Invalid)?;
        if state.phase != ConsentPhase::Active {
            return Err(Invalid);
        }
        revoker.arm();
        state.phase = ConsentPhase::Frozen;
        state.revoker = Some(revoker);
        Ok(())
    }
    fn revoke(&self) -> Option<crate::pairing_pending::AdmissionRevoker> {
        let Ok(mut state) = self.0.lock() else {
            return None;
        };
        if let Some(revoker) = state.revoker.as_mut() {
            revoker.mark_revoking();
        }
        state.phase = ConsentPhase::Revoked;
        state.revoker.take()
    }
}
#[cfg(test)]
#[derive(Clone)]
struct EndpointDropPause {
    reached: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}
#[cfg(test)]
struct EndpointDropPauseHandle(EndpointDropPause);
#[cfg(test)]
impl EndpointDropPauseHandle {
    fn release(self) {
        self.0.release.wait();
    }
}
impl ProvisionalEndpoint {
    pub fn bind(
        address: std::net::SocketAddr,
        certificate: Vec<u8>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, Invalid> {
        let (server, client) = configs(certificate, key)?;
        let endpoint = quinn::Endpoint::server(server, address).map_err(|_| Invalid)?;
        Ok(Self {
            endpoint,
            client,
            owner: process_owner(),
            scope: Arc::new(ConsentScope::new()),
            #[cfg(test)]
            drop_pause: None,
        })
    }
    #[cfg(test)]
    fn test_pause_drop_after_scope_revocation(&mut self) -> EndpointDropPauseHandle {
        let pause = EndpointDropPause {
            reached: Arc::new(std::sync::Barrier::new(2)),
            release: Arc::new(std::sync::Barrier::new(2)),
        };
        self.drop_pause = Some(pause.clone());
        EndpointDropPauseHandle(pause)
    }
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, Invalid> {
        self.endpoint.local_addr().map_err(|_| Invalid)
    }
    pub async fn connect(&self, peer: std::net::SocketAddr) -> Result<ProvisionalChannel, Invalid> {
        let (config, auth) = self.client.fresh()?;
        let generation = self.owner.generation()?;
        let connecting = self
            .endpoint
            .connect_with(config, peer, "pairing.local")
            .map_err(|_| Invalid)?;
        let connection = tokio::time::timeout(std::time::Duration::from_secs(30), connecting)
            .await
            .map_err(|_| Invalid)?
            .map_err(|_| Invalid)?;
        if !auth.requested.load(Ordering::Acquire) {
            connection.close(2u32.into(), b"mutual authentication required");
            return Err(Invalid);
        }
        ProvisionalChannel::observe(
            connection,
            generation,
            self.owner,
            self.scope.clone(),
            self.client.identity()?,
        )
    }
    pub async fn accept(&self) -> Result<ProvisionalChannel, Invalid> {
        let generation = self.owner.generation()?;
        let connection = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            self.endpoint
                .accept()
                .await
                .ok_or(Invalid)?
                .await
                .map_err(|_| Invalid)
        })
        .await
        .map_err(|_| Invalid)??;
        ProvisionalChannel::observe(
            connection,
            generation,
            self.owner,
            self.scope.clone(),
            self.client.identity()?,
        )
    }
}
impl Drop for ProvisionalEndpoint {
    fn drop(&mut self) {
        let revoker = self.scope.revoke();
        #[cfg(test)]
        if let Some(pause) = self.drop_pause.take() {
            pause.reached.wait();
            pause.release.wait();
        }
        if let Some(mut revoker) = revoker {
            let _revocation_result = revoker.revoke();
        }
        self.endpoint.close(0u32.into(), b"consent scope closed");
    }
}
/// A channel cannot be adopted from an arbitrary external QUIC connection.
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::ProvisionalChannel;
/// fn adopt(c: &quinn::Connection) {
///     let _ = ProvisionalChannel::observe(c, 1, std::sync::Arc::default());
/// }
/// ```
/// Replay ownership cannot be supplied or reset by a caller.
/// ```compile_fail
/// use seamless_transport::pairing_v2::operational_binding::TransportReplayRegistry;
/// let _ = TransportReplayRegistry::default();
/// ```
/// ```compile_fail
/// use seamless_transport::pairing_v2::provisional_tls::ProvisionalChannel;
/// fn duplicate(c: ProvisionalChannel) { let _: ProvisionalChannel = c.clone(); }
/// ```
pub struct ProvisionalChannel {
    #[cfg(test)]
    fault: Option<handshake_io::WireFault>,
    local_identity: Arc<rustls::sign::CertifiedKey>,
    connection: quinn::Connection,
    leaf: Vec<u8>,
    id: String,
    generation: u64,
    owner: &'static ProcessOwner,
    scope: Arc<ConsentScope>,
    attempted: bool,
}
impl ProvisionalChannel {
    // Only the strict endpoint can mint this capability. No raw public adoption.
    fn observe(
        connection: quinn::Connection,
        generation: u64,
        owner: &'static ProcessOwner,
        scope: Arc<ConsentScope>,
        local_identity: Arc<rustls::sign::CertifiedKey>,
    ) -> Result<Self, Invalid> {
        let observed = (|| {
            if connection.close_reason().is_some() {
                return Err(Invalid);
            }
            let handshake = connection
                .handshake_data()
                .ok_or(Invalid)?
                .downcast::<quinn::crypto::rustls::HandshakeData>()
                .map_err(|_| Invalid)?;
            if handshake.protocol.as_deref() != Some(ALPN) {
                return Err(Invalid);
            }
            let certs = connection
                .peer_identity()
                .ok_or(Invalid)?
                .downcast::<Vec<CertificateDer<'static>>>()
                .map_err(|_| Invalid)?;
            if certs.len() != 1 {
                return Err(Invalid);
            }
            let leaf = certs[0].as_ref().to_vec();
            profile(&leaf, utc()?)?;
            Ok(leaf)
        })();
        let leaf = match observed {
            Ok(leaf) => leaf,
            Err(error) => {
                connection.close(2u32.into(), b"provisional identity rejected");
                return Err(error);
            }
        };
        Ok(Self {
            local_identity,
            #[cfg(test)]
            fault: None,
            id: format!("quic-{}", connection.stable_id()),
            connection,
            leaf,
            generation,
            owner,
            scope,
            attempted: false,
        })
    }
    pub fn connection_id(&self) -> &str {
        &self.id
    }
    pub fn bind(&mut self, request: &[u8], hello: &[u8]) -> Result<LocalBinding, Invalid> {
        let result = (|| {
            // Linearize binding against scope revocation, independently of the
            // asynchronous QUIC close notification. Poison is fail-closed.
            if !self.scope.is_active()?
                || self.attempted
                || self.connection.close_reason().is_some()
            {
                return Err(Invalid);
            }
            self.attempted = true;
            let input =
                BindingInput::new(request, hello, &self.leaf, &self.id, self.generation, ALPN)?;
            let mut exporter = zeroize::Zeroizing::new([0u8; 32]);
            self.connection
                .export_keying_material(exporter.as_mut(), EXPORTER_LABEL, input.exporter_context())
                .map_err(|_| Invalid)?;
            let binding = input.finish(exporter)?;
            self.owner.replay.consume(&binding)?;
            Ok(binding)
        })();
        if result.is_err() {
            self.connection
                .close(2u32.into(), b"provisional binding rejected");
        }
        result
    }
}
impl Drop for ProvisionalChannel {
    fn drop(&mut self) {
        self.connection
            .close(0u32.into(), b"provisional boundary closed");
    }
}
