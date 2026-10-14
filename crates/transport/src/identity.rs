use crate::pairing::PairingError;
use crate::quic::{PeerIdentityVerifier, TransportError};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use seamless_input_protocol::NodeId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const IDENTITY_FILE: &str = "identity.json";
const PEERS_FILE: &str = "peers.json";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedPeer {
    pub node_id: NodeId,
    pub friendly_name: String,
    pub public_identity: Vec<u8>,
    pub certificate_pin: [u8; 32],
}
impl PinnedPeer {
    pub fn from_identity(identity: &IdentityStore) -> Self {
        Self {
            node_id: identity.node_id(),
            friendly_name: identity.friendly_name().to_owned(),
            public_identity: identity.certificate_der().to_vec(),
            certificate_pin: identity.certificate_pin(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    friendly_name: String,
    certificate_der: String,
    private_key_der: String,
    private_key_protection: String,
}
#[derive(Serialize, Deserialize)]
struct StoredPeer {
    node_id: [u8; 16],
    friendly_name: String,
    public_identity: String,
    certificate_pin: [u8; 32],
}

pub struct IdentityStore {
    root: PathBuf,
    friendly_name: String,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    peers: BTreeMap<NodeId, PinnedPeer>,
}

#[derive(Clone, Debug)]
pub struct PinnedIdentityVerifier {
    pins: BTreeMap<NodeId, [u8; 32]>,
}

impl PeerIdentityVerifier for PinnedIdentityVerifier {
    fn verify(
        &self,
        connection: &quinn::Connection,
        claimed: NodeId,
    ) -> Result<(), TransportError> {
        let expected = self
            .pins
            .get(&claimed)
            .ok_or(TransportError::IdentityRejected)?;
        let identity = connection
            .peer_identity()
            .ok_or(TransportError::IdentityRejected)?;
        let certificates = identity
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .map_err(|_| TransportError::IdentityRejected)?;
        let certificate = certificates
            .first()
            .ok_or(TransportError::IdentityRejected)?;
        let pin: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
        if &pin != expected {
            return Err(TransportError::IdentityRejected);
        }
        let mut node = [0; 16];
        node.copy_from_slice(&pin[..16]);
        if claimed != NodeId(node) {
            return Err(TransportError::IdentityRejected);
        }
        Ok(())
    }
}
impl IdentityStore {
    pub fn open_or_create(
        root: impl AsRef<Path>,
        friendly_name: &str,
    ) -> Result<Self, PairingError> {
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let path = root.join(IDENTITY_FILE);
        let stored = if path.exists() {
            harden_private_file(&path)?;
            serde_json::from_slice::<StoredIdentity>(&fs::read(&path)?)?
        } else {
            let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
            let certificate = rcgen::CertificateParams::new(vec!["seamless-input.local".into()])?
                .self_signed(&signing_key)?;
            let stored = StoredIdentity {
                friendly_name: validate_name(friendly_name)?.to_owned(),
                certificate_der: STANDARD.encode(certificate.der()),
                private_key_der: STANDARD
                    .encode(protect_private_key(&signing_key.serialize_der())?),
                private_key_protection: private_key_protection().to_owned(),
            };
            write_private_json(&path, &stored)?;
            stored
        };
        let certificate_der = STANDARD.decode(stored.certificate_der)?;
        if stored.private_key_protection != private_key_protection() {
            return Err(PairingError::InvalidIdentity);
        }
        let private_key_der = unprotect_private_key(&STANDARD.decode(stored.private_key_der)?)?;
        let peers = read_peers(&root.join(PEERS_FILE))?;
        Ok(Self {
            root,
            friendly_name: stored.friendly_name,
            certificate_der,
            private_key_der,
            peers,
        })
    }
    pub fn node_id(&self) -> NodeId {
        let digest = Sha256::digest(&self.certificate_der);
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        NodeId(id)
    }
    pub fn friendly_name(&self) -> &str {
        &self.friendly_name
    }
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
    pub fn certificate_pin(&self) -> [u8; 32] {
        Sha256::digest(&self.certificate_der).into()
    }
    pub fn peer(&self, id: NodeId) -> Option<&PinnedPeer> {
        self.peers.get(&id)
    }
    pub fn peers(&self) -> impl Iterator<Item = &PinnedPeer> {
        self.peers.values()
    }
    pub fn verifier(&self) -> PinnedIdentityVerifier {
        PinnedIdentityVerifier {
            pins: self
                .peers
                .iter()
                .map(|(id, peer)| (*id, peer.certificate_pin))
                .collect(),
        }
    }
    pub fn pin_peer(&mut self, peer: PinnedPeer) -> Result<(), PairingError> {
        validate_peer(&peer)?;
        let mut proposed = self.peers.clone();
        proposed.insert(peer.node_id, peer);
        self.save_peers(&proposed)?;
        self.peers = proposed;
        Ok(())
    }
    pub fn unpair(&mut self, id: NodeId) -> Result<bool, PairingError> {
        let mut proposed = self.peers.clone();
        let removed = proposed.remove(&id).is_some();
        if removed {
            self.save_peers(&proposed)?;
            self.peers = proposed;
        }
        Ok(removed)
    }
    pub fn validate_peer_certificate(
        &self,
        peer: &PinnedPeer,
        certificate: &[u8],
    ) -> Result<(), PairingError> {
        let pin: [u8; 32] = Sha256::digest(certificate).into();
        if pin != peer.certificate_pin || certificate != peer.public_identity {
            Err(PairingError::PinMismatch)
        } else {
            Ok(())
        }
    }
    pub fn quic_configs_for(
        &self,
        peer: &PinnedPeer,
    ) -> Result<(quinn::ServerConfig, quinn::ClientConfig), PairingError> {
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rustls::{
            RootCertStore,
            pki_types::{CertificateDer, PrivatePkcs8KeyDer},
        };
        self.validate_peer_certificate(peer, &peer.public_identity)?;
        let own_cert = CertificateDer::from(self.certificate_der.clone());
        let own_key = PrivatePkcs8KeyDer::from(self.private_key_der.clone()).into();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(peer.public_identity.clone()))
            .map_err(|_| PairingError::Tls)?;
        let roots = std::sync::Arc::new(roots);
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots.clone())
            .build()
            .map_err(|_| PairingError::Tls)?;
        let server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![own_cert.clone()], own_key)
            .map_err(|_| PairingError::Tls)?;
        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![own_cert],
                PrivatePkcs8KeyDer::from(self.private_key_der.clone()).into(),
            )
            .map_err(|_| PairingError::Tls)?;
        let server = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
            QuicServerConfig::try_from(server_crypto).map_err(|_| PairingError::Tls)?,
        ));
        let client = quinn::ClientConfig::new(std::sync::Arc::new(
            QuicClientConfig::try_from(client_crypto).map_err(|_| PairingError::Tls)?,
        ));
        Ok((server, client))
    }
    fn save_peers(&self, peers: &BTreeMap<NodeId, PinnedPeer>) -> Result<(), PairingError> {
        let stored: Vec<_> = peers
            .values()
            .map(|p| StoredPeer {
                node_id: p.node_id.0,
                friendly_name: p.friendly_name.clone(),
                public_identity: STANDARD.encode(&p.public_identity),
                certificate_pin: p.certificate_pin,
            })
            .collect();
        write_private_json(&self.root.join(PEERS_FILE), &stored)
    }
}

fn validate_name(name: &str) -> Result<&str, PairingError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        Err(PairingError::InvalidIdentity)
    } else {
        Ok(name)
    }
}
fn validate_peer(peer: &PinnedPeer) -> Result<(), PairingError> {
    validate_name(&peer.friendly_name)?;
    if peer.public_identity.is_empty() || peer.node_id == NodeId([0; 16]) {
        return Err(PairingError::InvalidIdentity);
    }
    let pin: [u8; 32] = Sha256::digest(&peer.public_identity).into();
    if pin != peer.certificate_pin {
        return Err(PairingError::PinMismatch);
    }
    let mut id = [0; 16];
    id.copy_from_slice(&pin[..16]);
    if peer.node_id != NodeId(id) {
        return Err(PairingError::InvalidIdentity);
    }
    Ok(())
}
fn read_peers(path: &Path) -> Result<BTreeMap<NodeId, PinnedPeer>, PairingError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    harden_private_file(path)?;
    let stored: Vec<StoredPeer> = serde_json::from_slice(&fs::read(path)?)?;
    let mut peers = BTreeMap::new();
    for s in stored {
        let peer = PinnedPeer {
            node_id: NodeId(s.node_id),
            friendly_name: s.friendly_name,
            public_identity: STANDARD.decode(s.public_identity)?,
            certificate_pin: s.certificate_pin,
        };
        validate_peer(&peer)?;
        if peers.insert(peer.node_id, peer).is_some() {
            return Err(PairingError::InvalidIdentity);
        }
    }
    Ok(peers)
}
fn create_private_directory(path: &Path) -> Result<(), PairingError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn harden_private_file(path: &Path) -> Result<(), PairingError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), PairingError> {
    let bytes = serde_json::to_vec(value)?;
    let parent = path.parent().ok_or(PairingError::InvalidIdentity)?;
    let mut random = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
    let tmp = parent.join(format!(
        ".seamless-input-{}.tmp",
        u64::from_ne_bytes(random)
    ));
    let result = write_and_replace(&tmp, path, &bytes);
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    Ok(())
}

fn write_and_replace(tmp: &Path, path: &Path, bytes: &[u8]) -> Result<(), PairingError> {
    use std::{fs::OpenOptions, io::Write};
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    drop(file);
    atomic_replace(tmp, path)?;
    #[cfg(unix)]
    {
        // The rename is the atomic commit point. Directory sync is best-effort:
        // reporting failure after that point would leave disk and memory disagreeing.
        if let Some(parent) = path.parent()
            && let Ok(directory) = std::fs::File::open(parent)
        {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_replace(tmp: &Path, path: &Path) -> Result<(), std::io::Error> {
    fs::rename(tmp, path)
}

#[cfg(windows)]
fn atomic_replace(tmp: &Path, path: &Path) -> Result<(), std::io::Error> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let from: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn private_key_protection() -> &'static str {
    "plaintext-owner-only"
}

#[cfg(windows)]
fn private_key_protection() -> &'static str {
    "dpapi-current-user"
}

#[cfg(not(windows))]
fn protect_private_key(key: &[u8]) -> Result<Vec<u8>, PairingError> {
    Ok(key.to_vec())
}

#[cfg(not(windows))]
fn unprotect_private_key(key: &[u8]) -> Result<Vec<u8>, PairingError> {
    Ok(key.to_vec())
}

#[cfg(windows)]
fn protect_private_key(key: &[u8]) -> Result<Vec<u8>, PairingError> {
    dpapi_transform(key, true)
}

#[cfg(windows)]
fn unprotect_private_key(key: &[u8]) -> Result<Vec<u8>, PairingError> {
    dpapi_transform(key, false)
}

#[cfg(windows)]
fn dpapi_transform(data: &[u8], protect: bool) -> Result<Vec<u8>, PairingError> {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| PairingError::InvalidIdentity)?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(PairingError::Io(std::io::Error::last_os_error()));
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData.cast()) };
    input.pbData = ptr::null_mut();
    Ok(result)
}
