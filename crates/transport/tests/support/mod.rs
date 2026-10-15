use quinn::{ClientConfig, ServerConfig};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::sync::Arc;

// A generated test certificate authenticates TLS but deliberately does not
// bind NodeId to a paired identity. Task 3 sessions therefore stay pending.
#[allow(
    dead_code,
    reason = "shared fixture used by simultaneous integration tests"
)]
pub fn configs() -> (ServerConfig, ClientConfig) {
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    configs_from_der(cert.cert.der().to_vec(), cert.signing_key.serialize_der())
}

pub fn configs_from_der(cert: Vec<u8>, key: Vec<u8>) -> (ServerConfig, ClientConfig) {
    let cert = rustls::pki_types::CertificateDer::from(cert);
    let server =
        ServerConfig::with_single_cert(vec![cert.clone()], PrivatePkcs8KeyDer::from(key).into())
            .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    (server, client)
}
