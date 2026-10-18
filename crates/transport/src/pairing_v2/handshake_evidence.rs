//! Private live evidence encoder; not an admission or signing capability.
use super::{
    DOMAIN, DerivedKeys, EvidenceContext, Invalid, Role, SignedEvidence,
    codec::{Value, decode, encode},
    evidence::{b, t},
};
use std::sync::Arc;
pub(super) type Sign<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>, Invalid>;
pub(super) struct LiveEvidence {
    pub context: EvidenceContext,
    pub keys: Arc<DerivedKeys>,
}
impl LiveEvidence {
    fn signed(&self, role: Role, body: Vec<u8>, sign: Sign<'_>) -> Result<SignedEvidence, Invalid> {
        let signature = sign(&body)?;
        self.context.identities[role.index()].verify(&body, &signature)?;
        Ok(SignedEvidence { body, signature })
    }
    fn wrapped(
        &self,
        role: Role,
        wire: &str,
        tag_kind: &str,
        record: SignedEvidence,
    ) -> Result<Vec<u8>, Invalid> {
        let tag = self.keys.confirm_tag(
            role,
            &encode(tag_kind, &[b(&record.body), b(&record.signature)])?,
        )?;
        encode(wire, &[b(&record.body), b(&record.signature), b(&tag)])
    }
    pub fn key_proof(&self, role: Role, sign: Sign<'_>) -> Result<Vec<u8>, Invalid> {
        let record = self.signed(
            role,
            encode(
                "key-proof-body",
                &[
                    t(DOMAIN),
                    b(&self.context.attempt),
                    b(&self.context.transcript),
                    t(role.text()),
                ],
            )?,
            sign,
        )?;
        let tag = self.keys.confirm_tag(
            role,
            &encode(
                "key-proof-tag",
                &[
                    t(DOMAIN),
                    b(&self.context.attempt),
                    b(&self.context.transcript),
                    t(role.text()),
                    b(&record.signature),
                ],
            )?,
        )?;
        encode(
            "wire-key-proof-v1",
            &[b(&record.body), b(&record.signature), b(&tag)],
        )
    }
    pub fn approval(&self, role: Role, sign: Sign<'_>) -> Result<Vec<u8>, Invalid> {
        let record = self.signed(
            role,
            encode(
                "human-decision",
                &[
                    t(DOMAIN),
                    b(&self.context.attempt),
                    b(&self.context.transcript),
                    t(role.text()),
                    t("match"),
                    Value::Number(1),
                ],
            )?,
            sign,
        )?;
        self.wrapped(role, "wire-approval-v1", "approve-tag", record)
    }
    pub fn finalization(
        &self,
        phase: &str,
        role: Role,
        p: [u8; 32],
        sign: Sign<'_>,
    ) -> Result<Vec<u8>, Invalid> {
        let record = self.signed(
            role,
            encode(
                "finalization-body",
                &[
                    t(DOMAIN),
                    t(phase),
                    b(&self.context.attempt),
                    b(&self.context.transcript),
                    b(&p),
                    t(role.text()),
                ],
            )?,
            sign,
        )?;
        self.context
            .verify_finalization(phase, role, p, &record, None)?;
        self.wrapped(role, "wire-finalization-v1", "finalization-tag", record)
    }
    fn cancel_body(&self, role: Role) -> Result<Vec<u8>, Invalid> {
        encode(
            "cancel-body-v1",
            &[
                t(DOMAIN),
                b(&self.context.attempt),
                b(&self.context.transcript),
                t(role.text()),
                t("user-cancelled"),
                Value::Number(1),
            ],
        )
    }
    pub fn cancel(&self, role: Role, sign: Sign<'_>) -> Result<Vec<u8>, Invalid> {
        self.wrapped(
            role,
            "wire-cancel-v1",
            "cancel-tag-v1",
            self.signed(role, self.cancel_body(role)?, sign)?,
        )
    }
    pub fn verify_cancel(&self, role: Role, raw: &[u8]) -> Result<(), Invalid> {
        let (record, tag) = unwrap("wire-cancel-v1", raw)?;
        if record.body != self.cancel_body(role)? {
            return Err(Invalid);
        }
        self.context.identities[role.index()].verify(&record.body, &record.signature)?;
        self.keys.verify_confirm_tag(
            role,
            &encode("cancel-tag-v1", &[b(&record.body), b(&record.signature)])?,
            &tag,
        )
    }
}
pub(super) fn unwrap(kind: &str, raw: &[u8]) -> Result<(SignedEvidence, Vec<u8>), Invalid> {
    let values = decode(kind, raw, &[2, 2, 2])?;
    let [
        Value::Bytes(body),
        Value::Bytes(signature),
        Value::Bytes(tag),
    ]: [Value; 3] = values.try_into().map_err(|_| Invalid)?
    else {
        return Err(Invalid);
    };
    if signature.len() != 64 || tag.len() != 32 {
        return Err(Invalid);
    }
    Ok((SignedEvidence { body, signature }, tag))
}
#[cfg(test)]
mod tests;
