#![cfg(feature = "pairing-v2-experimental")]

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use seamless_input::guided_setup::SetupError;
use seamless_input::{
    guided_setup::PairingDiscoveryWindow, product_pairing_adapter::PairingAdvertisementLease,
};

fn identity() -> (Vec<u8>, PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut certificate = rcgen::CertificateParams::default();
    certificate.is_ca = rcgen::IsCa::ExplicitNoCa;
    certificate.subject_alt_names = vec![rcgen::SanType::URI(
        "urn:control-shift-f12:identity".try_into().unwrap(),
    )];
    certificate.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let certificate = certificate.self_signed(&key).unwrap().der().to_vec();
    (
        certificate,
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
}

// This exercises real mDNS and the strict provisional endpoint. Most fault and
// ordering cases use deterministic publication resources in the module tests.
#[tokio::test]
async fn closing_the_pairing_window_withdraws_publication_and_drops_the_listener() {
    let (certificate, key) = identity();
    let mut window = PairingDiscoveryWindow::default();
    let generation = window.open(10).unwrap();
    let lease =
        PairingAdvertisementLease::open(&mut window, generation, 10, certificate, key).unwrap();
    assert!(lease.is_active());
    window.close(11).unwrap();
    assert!(!lease.is_active());
    assert_eq!(lease.generation(), generation);
}

#[test]
fn opening_without_an_engine_runtime_returns_a_redacted_error() {
    let (certificate, key) = identity();
    let mut window = PairingDiscoveryWindow::default();
    let generation = window.open(10).unwrap();
    assert!(matches!(
        PairingAdvertisementLease::open(&mut window, generation, 10, certificate, key),
        Err(SetupError::Unavailable)
    ));
}
