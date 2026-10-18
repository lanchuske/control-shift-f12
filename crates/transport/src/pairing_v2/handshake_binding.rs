//! Frozen bilateral context; observations come from the sealed transport owner.
use super::{
    BoundHello, CandidateBinding, CandidateHello, Invalid, Role,
    codec::{Value, encode},
    evidence::{b, hash, t},
    operational_binding::BindingInput,
    operational_wire::ALPN,
    validate_identity,
};
#[cfg(test)]
mod tests;
pub(super) const SHARED_EXPORTER_LABEL: &[u8] = b"EXPORTER-ControlShiftF12-Handshake-v2";
pub(super) struct CandidateTranscript {
    pub(super) requests: [Vec<u8>; 2],
    pub(super) candidates: [Vec<u8>; 2],
    pub(super) observed: [Vec<u8>; 2],
}
impl CandidateTranscript {
    pub fn new(
        requests: [Vec<u8>; 2],
        candidates: [Vec<u8>; 2],
        observed: [Vec<u8>; 2],
        utc: i64,
    ) -> Result<Self, Invalid> {
        let fingerprints = observed.each_ref().map(|der| hash(der));
        if fingerprints[0] >= fingerprints[1] {
            return Err(Invalid);
        }
        for i in 0..2 {
            validate_identity(
                &observed[i],
                fingerprints[i][..16].try_into().map_err(|_| Invalid)?,
                utc,
            )?;
            // Request A addresses Candidate B and conversely. Reuse strict request/
            // echo/rendezvous/singleton-suite/observed-leaf checks, not claimed equality.
            BindingInput::new(
                &requests[1 - i],
                &candidates[i],
                &observed[i],
                "quic-candidate-check",
                0,
                ALPN,
            )?;
        }
        Ok(Self {
            requests,
            candidates,
            observed,
        })
    }
    pub fn exporter_context(&self) -> Result<Vec<u8>, Invalid> {
        encode(
            "handshake-exporter-context-v2",
            &[
                b(&hash(&self.requests[0])),
                b(&hash(&self.candidates[1])),
                b(&hash(&self.requests[1])),
                b(&hash(&self.candidates[0])),
                b(&hash(&self.observed[0])),
                b(&hash(&self.observed[1])),
                t("csf12-pair/2"),
            ],
        )
    }
    pub fn local_binding(
        &self,
        role: Role,
        id: &str,
        generation: u64,
        exporter: &[u8; 32],
    ) -> Result<[u8; 32], Invalid> {
        CandidateBinding::select(
            &CandidateHello::decode(&self.candidates[role.index()])?,
            id,
            generation,
        )?;
        let mut fields = vec![t(role.text()), t(id), Value::Number(generation)];
        let offset = encode("local-selected-connection-v1", &fields)?.len() + 7;
        fields.extend([
            b(&[0; 32]),
            b(&hash(&self.candidates[0])),
            b(&hash(&self.candidates[1])),
        ]);
        let mut bytes = zeroize::Zeroizing::new(encode("local-selected-connection-v1", &fields)?);
        bytes
            .get_mut(offset..offset + 32)
            .ok_or(Invalid)?
            .copy_from_slice(exporter);
        Ok(hash(&bytes))
    }
    pub fn bind_hello(
        &self,
        role: Role,
        hello: &[u8],
        id: &str,
        generation: u64,
        utc: i64,
    ) -> Result<BoundHello, Invalid> {
        let i = role.index();
        let candidate = CandidateHello::decode(&self.candidates[i])?;
        let binding = CandidateBinding::select(&candidate, id, generation)?;
        let fingerprint = hash(&self.observed[i]);
        BoundHello::validate(
            &candidate,
            &binding,
            hello,
            fingerprint,
            id,
            generation,
            fingerprint[..16].try_into().map_err(|_| Invalid)?,
            utc,
        )
    }
}
