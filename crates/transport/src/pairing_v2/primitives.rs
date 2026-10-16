//! Byte interoperability primitives. No handshake ordering or candidate-authentication claim.
use super::{
    DOMAIN, EvidenceContext, Invalid, Role, SAS_FORMAT, SUITE, WORDLIST_HASH,
    codec::{Value, decode, encode},
    evidence::{b, hash, t},
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;
pub struct DerivedKeys {
    sas: Zeroizing<[u8; 32]>,
    confirm: [Zeroizing<[u8; 32]>; 2],
    transcript: [u8; 32],
}
type DetachedHashes = ([u8; 32], [u8; 32], [u8; 32]);
/// Recomputes frozen C/attempt/T and commitments only; not a live handshake API.
pub fn detached_transcript(
    a: &[u8],
    b_hello: &[u8],
    commits: [&[u8]; 2],
    reveals: [&[u8]; 2],
) -> Result<DetachedHashes, Invalid> {
    let mut fingerprints = vec![];
    for raw in [a, b_hello] {
        let fields = decode("hello", raw, &[1, 2, 2, 2, 2, 2, 2, 3, 2, 3, 3, 2, 3, 1])?;
        if fields[0] != Value::Number(2)
            || fields[9..]
                != [
                    t(SUITE),
                    t(SAS_FORMAT),
                    b(&WORDLIST_HASH),
                    t("compare_v2_required"),
                    Value::Number(300),
                ]
        {
            return Err(Invalid);
        }
        let Value::Bytes(cert) = &fields[8] else {
            return Err(Invalid);
        };
        fingerprints.push(hash(cert));
    }
    if fingerprints[0] >= fingerprints[1] {
        return Err(Invalid);
    }
    let c = hash(&encode(
        "context",
        &[t(DOMAIN), b(a), b(b_hello), t(SUITE), t("A,B")],
    )?);
    let attempt = hash(&encode("attempt", &[t(DOMAIN), b(&c)])?);
    for (i, role) in [Role::A, Role::B].into_iter().enumerate() {
        let reveal = decode("reveal", reveals[i], &[2, 3, 2, 2])?;
        let commit = decode("commit", commits[i], &[2, 3, 2])?;
        if reveal[..2] != [b(&attempt), t(role.text())]
            || commit[..2] != [b(&attempt), t(role.text())]
        {
            return Err(Invalid);
        }
        let (Value::Bytes(pk), Value::Bytes(blind)) = (&reveal[2], &reveal[3]) else {
            return Err(Invalid);
        };
        if pk.len() != 32 || blind.len() != 32 {
            return Err(Invalid);
        }
        let commitment = hash(&encode(
            "commit-body",
            &[t(DOMAIN), b(&c), t(role.text()), b(pk), b(blind)],
        )?);
        if commit[2] != b(&commitment) {
            return Err(Invalid);
        }
    }
    let transcript = hash(&encode(
        "transcript",
        &[
            t(DOMAIN),
            b(&c),
            b(commits[0]),
            b(commits[1]),
            b(reveals[0]),
            b(reveals[1]),
        ],
    )?);
    Ok((c, attempt, transcript))
}
fn mac(key: &[u8], body: &[u8]) -> Result<[u8; 32], Invalid> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Invalid)?;
    m.update(body);
    Ok(m.finalize().into_bytes().into())
}
pub fn derive_keys(
    private: Zeroizing<[u8; 32]>,
    peer: [u8; 32],
    transcript: [u8; 32],
) -> Result<DerivedKeys, Invalid> {
    let shared = Zeroizing::new(MontgomeryPoint(peer).mul_clamped(*private).to_bytes());
    if *shared == [0; 32] {
        return Err(Invalid);
    }
    let prk = Zeroizing::new(mac(&transcript, shared.as_ref())?);
    let expand = |label: &str| -> Result<Zeroizing<[u8; 32]>, Invalid> {
        let mut info = encode("kdf-label", &[t(DOMAIN), t(label), b(&transcript)])?;
        info.push(1);
        Ok(Zeroizing::new(mac(prk.as_ref(), &info)?))
    };
    Ok(DerivedKeys {
        sas: expand("sas")?,
        confirm: [expand("confirm-A")?, expand("confirm-B")?],
        transcript,
    })
}
impl DerivedKeys {
    pub(super) fn verify_finalization(
        &self,
        context: &EvidenceContext,
        phase: &str,
        role: Role,
        p: [u8; 32],
        record: &super::SignedEvidence,
        tag: &[u8],
    ) -> Result<(), Invalid> {
        if context.transcript != self.transcript {
            return Err(Invalid);
        }
        context.verify_finalization(
            phase,
            role,
            p,
            record,
            Some((self.confirm[role.index()].as_ref(), tag)),
        )
    }
    pub(super) fn verify_approval(
        &self,
        context: &EvidenceContext,
        role: Role,
        record: &super::SignedEvidence,
        tag: &[u8],
    ) -> Result<(), Invalid> {
        if context.transcript != self.transcript {
            return Err(Invalid);
        }
        context.verify_approval(
            role,
            record,
            Some((self.confirm[role.index()].as_ref(), tag)),
        )
    }
    pub fn sas_digest(&self, attempt: [u8; 32]) -> Result<[u8; 32], Invalid> {
        mac(
            self.sas.as_ref(),
            &encode(
                "display",
                &[t(DOMAIN), b(&attempt), b(&self.transcript), t(SAS_FORMAT)],
            )?,
        )
    }
}
impl EvidenceContext {
    pub fn verify_key_proof(
        &self,
        role: Role,
        signature: &[u8],
        tag: &[u8],
        keys: &DerivedKeys,
    ) -> Result<(), Invalid> {
        if self.transcript != keys.transcript {
            return Err(Invalid);
        }
        self.identities[role.index()].verify(
            &encode(
                "key-proof-body",
                &[
                    t(DOMAIN),
                    b(&self.attempt),
                    b(&self.transcript),
                    t(role.text()),
                ],
            )?,
            signature,
        )?;
        let mut m = Hmac::<Sha256>::new_from_slice(keys.confirm[role.index()].as_ref())
            .map_err(|_| Invalid)?;
        m.update(&encode(
            "key-proof-tag",
            &[
                t(DOMAIN),
                b(&self.attempt),
                b(&self.transcript),
                t(role.text()),
                b(signature),
            ],
        )?);
        m.verify_slice(tag).map_err(|_| Invalid)
    }
}
