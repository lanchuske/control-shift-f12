use crate::{
    identity::{private_key_protection, protect_private_key, unprotect_private_key},
    pairing::PairingError,
    pairing_pending::StoreError,
    private_fs::PrivateDir,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::Path};
use zeroize::Zeroizing;

const IDENTITY_FILE: &str = "identity-v1.json";
const MAX_IDENTITY_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ProductIdentityError {
    #[error("product identity unavailable")]
    Unavailable,
    #[error("product identity invalid")]
    Invalid,
}

impl From<StoreError> for ProductIdentityError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Invalid | StoreError::Limit => Self::Invalid,
            _ => Self::Unavailable,
        }
    }
}

impl From<PairingError> for ProductIdentityError {
    fn from(_: PairingError) -> Self {
        Self::Invalid
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentity {
    version: u8,
    certificate_der: String,
    protected_private_key_der: String,
    private_key_protection: String,
}

/// Persistent product identity shared by G4 bootstrap and fresh operational
/// verification. Key bytes stay private to the transport crate.
pub struct ProductIdentity {
    certificate: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl ProductIdentity {
    pub fn open_or_create(root: &Path) -> Result<Self, ProductIdentityError> {
        let directory = PrivateDir::root(root)?;
        let stored = match directory.read(IDENTITY_FILE, MAX_IDENTITY_BYTES)? {
            Some(bytes) => serde_json::from_slice::<StoredIdentity>(&bytes)
                .map_err(|_| ProductIdentityError::Invalid)?,
            None => {
                let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
                    .map_err(|_| ProductIdentityError::Unavailable)?;
                let mut parameters = rcgen::CertificateParams::default();
                parameters.is_ca = rcgen::IsCa::ExplicitNoCa;
                parameters.subject_alt_names = vec![rcgen::SanType::URI(
                    "urn:control-shift-f12:identity"
                        .try_into()
                        .map_err(|_| ProductIdentityError::Invalid)?,
                )];
                parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
                let certificate = parameters
                    .self_signed(&key)
                    .map_err(|_| ProductIdentityError::Unavailable)?;
                let protected = protect_private_key(&key.serialize_der())?;
                let stored = StoredIdentity {
                    version: 1,
                    certificate_der: STANDARD.encode(certificate.der()),
                    protected_private_key_der: STANDARD.encode(protected),
                    private_key_protection: private_key_protection().to_owned(),
                };
                let bytes =
                    serde_json::to_vec(&stored).map_err(|_| ProductIdentityError::Unavailable)?;
                directory.replace(IDENTITY_FILE, &bytes)?;
                stored
            }
        };
        if stored.version != 1 || stored.private_key_protection != private_key_protection() {
            return Err(ProductIdentityError::Invalid);
        }
        let certificate = STANDARD
            .decode(stored.certificate_der)
            .map_err(|_| ProductIdentityError::Invalid)?;
        let protected = STANDARD
            .decode(stored.protected_private_key_der)
            .map_err(|_| ProductIdentityError::Invalid)?;
        let private_key = Zeroizing::new(unprotect_private_key(&protected)?);
        if certificate.is_empty() || private_key.is_empty() {
            return Err(ProductIdentityError::Invalid);
        }
        Ok(Self {
            certificate,
            private_key,
        })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.certificate).into()
    }

    pub fn bind_pairing(
        &self,
        address: SocketAddr,
    ) -> Result<super::provisional_tls::ProvisionalEndpoint, super::Invalid> {
        super::provisional_tls::ProvisionalEndpoint::bind(
            address,
            self.certificate.clone(),
            self.private_key_der(),
        )
    }

    #[cfg(feature = "pairing-v2-operational-experimental")]
    pub fn bind_operational(
        &self,
        address: SocketAddr,
    ) -> Result<ProductOperationalEndpoint, super::Invalid> {
        super::operational_session::OperationalEndpoint::bind(
            address,
            self.certificate.clone(),
            self.private_key_der(),
        )
        .map(|inner| ProductOperationalEndpoint { inner })
    }

    fn private_key_der(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.private_key.to_vec()).into()
    }
}

/// Opaque endpoint wrapper. The future product coordinator can consume it
/// inside this crate; callers cannot obtain a QUIC endpoint or key material.
#[cfg(feature = "pairing-v2-operational-experimental")]
pub struct ProductOperationalEndpoint {
    #[allow(dead_code)] // Consumed by the product V01 coordinator in the next plan task.
    pub(crate) inner: super::operational_session::OperationalEndpoint,
}

#[cfg(feature = "pairing-v2-operational-experimental")]
impl ProductOperationalEndpoint {
    pub async fn connect(
        &self,
        peer: SocketAddr,
        authority: &super::AdmissionAuthorityStore,
        admission: super::OperationalAdmission,
    ) -> Result<super::product_operational::ProductOperationalAttempt, super::Invalid> {
        let attempt = self
            .inner
            .connect_admitted(peer, authority, admission.attempt())
            .await?;
        super::product_operational::ProductOperationalAttempt::start(attempt)
    }

    pub async fn accept(
        &self,
        authority: &super::AdmissionAuthorityStore,
        admission: super::OperationalAdmission,
    ) -> Result<super::product_operational::ProductOperationalAttempt, super::Invalid> {
        let attempt = self
            .inner
            .accept_admitted(authority, admission.attempt())
            .await?;
        super::product_operational::ProductOperationalAttempt::start(attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::ProductIdentity;

    #[test]
    fn reopening_private_state_preserves_the_operational_fingerprint() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("g4-identity");
        let first = ProductIdentity::open_or_create(&state)
            .unwrap()
            .fingerprint();
        let second = ProductIdentity::open_or_create(&state)
            .unwrap()
            .fingerprint();

        assert_ne!(first, [0; 32]);
        assert_eq!(first, second);
    }

    #[cfg(unix)]
    #[test]
    fn identity_state_is_owner_only_and_rejects_a_linked_root() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("g4-identity");
        ProductIdentity::open_or_create(&state).unwrap();

        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(state.join("identity-v1.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let linked = root.path().join("linked-identity");
        symlink(&state, &linked).unwrap();
        assert!(ProductIdentity::open_or_create(&linked).is_err());
    }

    #[test]
    fn identity_file_has_a_small_bounded_encoding() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("g4-identity");
        ProductIdentity::open_or_create(&state).unwrap();
        let bytes = std::fs::read(state.join("identity-v1.json")).unwrap();

        assert!(!bytes.is_empty());
        assert!(bytes.len() <= 16 * 1024);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["version"],
            1
        );
    }
}
