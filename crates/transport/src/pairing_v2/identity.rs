use super::Invalid;
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    prelude::*,
};

// The maintained parser accepts some nonminimal length headers. Compare each
// parsed header with its canonical encoder, including constructed context tags.
fn canonical_headers(mut bytes: &[u8], depth: usize) -> Result<(), Invalid> {
    use asn1_rs::{Any, ToDer};
    if depth > 32 {
        return Err(Invalid);
    }
    while !bytes.is_empty() {
        let (remaining, object) = Any::from_der(bytes).map_err(|_| Invalid)?;
        let header_len = bytes.len() - remaining.len() - object.data.len();
        let mut canonical = vec![];
        object
            .header
            .write_der_header(&mut canonical)
            .map_err(|_| Invalid)?;
        if bytes[..header_len] != canonical {
            return Err(Invalid);
        }
        if object.header.is_constructed() {
            canonical_headers(object.data, depth + 1)?;
        }
        bytes = remaining;
    }
    Ok(())
}

/// Verified application certificate profile; not an active pin or admission token.
#[derive(Clone)]
pub struct Identity {
    fingerprint: [u8; 32],
    public_key: [u8; 32],
}
impl Identity {
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn verify(&self, body: &[u8], signature: &[u8]) -> Result<(), Invalid> {
        verify_ed25519(&self.public_key, body, signature)
    }
}

pub fn verify_ed25519(key: &[u8; 32], body: &[u8], signature: &[u8]) -> Result<(), Invalid> {
    let point = CompressedEdwardsY(*key).decompress().ok_or(Invalid)?;
    if point.compress().to_bytes() != *key
        || point.is_small_order()
        || !point.is_torsion_free()
        || signature.len() != 64
    {
        return Err(Invalid);
    }
    let encoded_r: [u8; 32] = signature[..32].try_into().map_err(|_| Invalid)?;
    let r = CompressedEdwardsY(encoded_r).decompress().ok_or(Invalid)?;
    if r.compress().to_bytes() != encoded_r || r.is_small_order() || !r.is_torsion_free() {
        return Err(Invalid);
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(body, signature)
        .map_err(|_| Invalid)
}

pub fn validate_identity(der: &[u8], node: [u8; 16], now: i64) -> Result<Identity, Invalid> {
    if der.is_empty() || der.len() > 8192 {
        return Err(Invalid);
    }
    canonical_headers(der, 0)?;
    let (rest, _) = der_parser::der::parse_der(der).map_err(|_| Invalid)?;
    if !rest.is_empty() {
        return Err(Invalid);
    }
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| Invalid)?;
    let ed = |a: &AlgorithmIdentifier<'_>| {
        a.algorithm.to_id_string() == "1.3.101.112" && a.parameters.is_none()
    };
    if !rest.is_empty()
        || cert.version() != X509Version::V3
        || cert.issuer() != cert.subject()
        || !ed(&cert.signature_algorithm)
        || !ed(&cert.tbs_certificate.signature)
        || !ed(&cert.public_key().algorithm)
        || cert.public_key().subject_public_key.unused_bits != 0
        || cert.signature_value.unused_bits != 0
        || now < cert.validity().not_before.timestamp()
        || now >= cert.validity().not_after.timestamp()
        || cert.extensions_map().is_err()
    {
        return Err(Invalid);
    }
    let mut basic = false;
    let mut usage = false;
    let mut san = false;
    for ext in cert.extensions() {
        // Parse the complete extension payload as DER too; no ignored trailing data.
        canonical_headers(ext.value, 0)?;
        let (remaining, _) = der_parser::der::parse_der(ext.value).map_err(|_| Invalid)?;
        if !remaining.is_empty() {
            return Err(Invalid);
        }
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(v) => {
                if v.ca || v.path_len_constraint.is_some() {
                    return Err(Invalid);
                }
                basic = true;
            }
            ParsedExtension::KeyUsage(v) => {
                if !v.digital_signature() || v.key_cert_sign() || v.crl_sign() {
                    return Err(Invalid);
                }
                usage = true;
            }
            ParsedExtension::SubjectAlternativeName(v) => {
                if v.general_names != [GeneralName::URI("urn:control-shift-f12:identity")] {
                    return Err(Invalid);
                }
                san = true;
            }
            ParsedExtension::ParseError { .. }
            | ParsedExtension::Unparsed
            | ParsedExtension::UnsupportedExtension { .. } => return Err(Invalid),
            _ if ext.critical => return Err(Invalid),
            _ => {}
        }
    }
    if !basic || !usage || !san {
        return Err(Invalid);
    }
    let public_key: [u8; 32] = cert
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| Invalid)?;
    verify_ed25519(
        &public_key,
        cert.tbs_certificate.as_ref(),
        cert.signature_value.data.as_ref(),
    )?;
    let fingerprint: [u8; 32] = Sha256::digest(der).into();
    if fingerprint[..16] != node {
        return Err(Invalid);
    }
    Ok(Identity {
        fingerprint,
        public_key,
    })
}
