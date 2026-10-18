//! Frozen local transport context primitives; not identity admission or shared
//! bilateral connection IDs. Production observation is in provisional_tls.
use super::Invalid;
use super::{
    CandidateBinding, CandidateHello, SUITE,
    codec::{Value, decode, encode},
    evidence::{b, hash, t},
    operational_wire::{ALPN, CandidateRequest},
};
use std::sync::Mutex;
#[cfg(test)]
#[path = "operational_binding_tests.rs"]
mod tests;
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-ControlShiftF12-Pairing-v2";
pub struct BindingInput {
    context: Vec<u8>,
    binding_fields: Vec<Value>,
    replay: [u8; 32],
}
impl BindingInput {
    /// Fixture-level primitive: callers supplying bytes do NOT thereby prove
    /// those bytes came from TLS. ProvisionalChannel owns that observation.
    pub fn new(
        request: &[u8],
        hello: &[u8],
        observed_leaf: &[u8],
        connection: &str,
        generation: u64,
        alpn: &[u8],
    ) -> Result<Self, Invalid> {
        let req = CandidateRequest::decode(request)?;
        let candidate = CandidateHello::decode(hello)?;
        let _ = CandidateBinding::select(&candidate, connection, generation)?;
        if alpn != ALPN || observed_leaf.is_empty() || observed_leaf.len() > 8192 {
            return Err(Invalid);
        }
        let fields = decode("candidate-hello", hello, &[2, 2, 2, 3, 3, 2, 2, 1])?;
        let mut singleton = vec![0, 1, 0, SUITE.len() as u8];
        singleton.extend(SUITE.as_bytes());
        let leaf = hash(observed_leaf);
        if fields[0] != b(&req.rendezvous)
            || fields[1] != b(&req.nonce)
            || fields[5] != b(&singleton)
            || fields[6] != b(&leaf)
        {
            return Err(Invalid);
        }
        let rh = hash(request);
        let hh = hash(hello);
        let context = encode(
            "tls-exporter-context-v1",
            &[
                b(&rh),
                b(&hh),
                b(&leaf),
                t(connection),
                Value::Number(generation),
                t("csf12-pair/2"),
            ],
        )?;
        let replay = hash(&encode(
            "transport-replay-token-v1",
            &[
                b(&rh),
                b(&hh),
                b(&req.nonce),
                fields[1].clone(),
                fields[2].clone(),
                t(connection),
                Value::Number(generation),
            ],
        )?);
        Ok(Self {
            context,
            binding_fields: vec![
                b(request),
                b(hello),
                b(observed_leaf),
                b(&leaf),
                t(connection),
                Value::Number(generation),
                t("csf12-pair/2"),
            ],
            replay,
        })
    }
    pub fn exporter_context(&self) -> &[u8] {
        &self.context
    }
    pub fn finish(&self, exporter: zeroize::Zeroizing<[u8; 32]>) -> Result<LocalBinding, Invalid> {
        let mut fields = self.binding_fields.clone();
        // Encode a zero placeholder, then populate only the guarded buffer's
        // final bytes32 field. The generic codec never clones exporter material.
        fields.push(b(&[0; 32]));
        let mut encoded = zeroize::Zeroizing::new(encode("operational-binding-v1", &fields)?);
        let end = encoded.len();
        encoded[end - 32..].copy_from_slice(exporter.as_ref());
        Ok(LocalBinding {
            digest: hash(&encoded),
            replay: self.replay,
        })
    }
}
pub struct LocalBinding {
    digest: [u8; 32],
    replay: [u8; 32],
}
impl LocalBinding {
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn replay_token(&self) -> &[u8; 32] {
        &self.replay
    }
}
#[derive(Default)]
pub(super) struct TransportReplayRegistry {
    used: Mutex<std::collections::HashSet<[u8; 32]>>,
}
impl TransportReplayRegistry {
    pub(super) fn consume_input(&self, input: &BindingInput) -> Result<(), Invalid> {
        let mut used = self.used.lock().map_err(|_| Invalid)?;
        if used.len() >= 1024 || !used.insert(input.replay) {
            return Err(Invalid);
        }
        Ok(())
    }
    /// Shared across live provisional channels in one process. No eviction or
    /// durable recovery promise; restart requires entirely fresh pairing/SAS.
    pub(super) fn consume(&self, binding: &LocalBinding) -> Result<(), Invalid> {
        let mut used = self.used.lock().map_err(|_| Invalid)?;
        if used.len() >= 1024 || !used.insert(binding.replay) {
            return Err(Invalid);
        }
        Ok(())
    }
}
