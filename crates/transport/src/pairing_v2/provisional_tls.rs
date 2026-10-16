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
use std::sync::Arc;
fn utc() -> Result<i64, Invalid> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Invalid)?
            .as_secs(),
    )
    .map_err(|_| Invalid)
}
fn profile(leaf: &[u8], now: i64) -> Result<(), Invalid> {
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
pub fn configs(
    certificate: Vec<u8>,
    key: PrivateKeyDer<'static>,
) -> Result<(quinn::ServerConfig, quinn::ClientConfig), Invalid> {
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
    server.alpn_protocols = vec![ALPN.to_vec()];
    server.max_early_data_size = 0;
    server.send_tls13_tickets = 0;
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Invalid)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)
        .map_err(|_| Invalid)?;
    client.alpn_protocols = vec![ALPN.to_vec()];
    client.enable_early_data = false;
    client.resumption = rustls::client::Resumption::disabled();
    let mut limits = quinn::TransportConfig::default();
    limits
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(1u32.into())
        .stream_receive_window(16_399u32.into())
        .receive_window(65_536u32.into())
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
    let mut client = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client).map_err(|_| Invalid)?,
    ));
    client.transport_config(limits);
    Ok((server, client))
}
pub struct ProvisionalChannel {
    connection: quinn::Connection,
    leaf: Vec<u8>,
    id: String,
    generation: u64,
    replay: Arc<TransportReplayRegistry>,
    attempted: bool,
}
impl ProvisionalChannel {
    /// Generation is caller-owned local lifecycle state, never peer input or a
    /// claim of a shared bilateral epoch. Use the strict configs above.
    pub fn observe(
        connection: &quinn::Connection,
        generation: u64,
        replay: Arc<TransportReplayRegistry>,
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
            connection: connection.clone(),
            leaf,
            id: format!("quic-{}", connection.stable_id()),
            generation,
            replay,
            attempted: false,
        })
    }
    pub fn connection_id(&self) -> &str {
        &self.id
    }
    pub fn bind(&mut self, request: &[u8], hello: &[u8]) -> Result<LocalBinding, Invalid> {
        let result = (|| {
            if self.attempted || self.connection.close_reason().is_some() {
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
            self.replay.consume(&binding)?;
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
