//! Addendum-1 parsing and connection-binding checks, not a discovery listener.
use super::{
    Invalid,
    codec::{Value, decode, encode},
    evidence::hash,
};
use unicode_normalization::UnicodeNormalization;
pub struct CandidateHello {
    encoded: Vec<u8>,
    fingerprint: [u8; 32],
}
fn safe_name(value: &str) -> Result<(), Invalid> {
    if value.is_empty() || value.len() > 80 || value.nfc().collect::<String>() != value {
        return Err(Invalid);
    }
    // Maintained Unicode category tables, not an incomplete hand-written bidi list.
    let hir = regex_syntax::Parser::new()
        // Surrogates (Cs) cannot occur in Rust UTF-8 strings and fail codec decoding.
        .parse(r"[\p{Cc}\p{Cf}]")
        .map_err(|_| Invalid)?;
    let regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(class)) = hir.kind()
    else {
        return Err(Invalid);
    };
    if value.chars().any(|c| {
        class
            .iter()
            .any(|range| range.start() <= c && c <= range.end())
    }) {
        return Err(Invalid);
    }
    Ok(())
}
fn suites(mut input: &[u8]) -> Result<(), Invalid> {
    if input.len() < 4 || input.len() > 512 {
        return Err(Invalid);
    }
    let count = u16::from_be_bytes([input[0], input[1]]);
    input = &input[2..];
    if !(1..=8).contains(&count) {
        return Err(Invalid);
    }
    let mut previous: &[u8] = &[];
    for _ in 0..count {
        if input.len() < 2 {
            return Err(Invalid);
        }
        let n = u16::from_be_bytes([input[0], input[1]]) as usize;
        input = &input[2..];
        if n == 0 || n > 64 || n > input.len() {
            return Err(Invalid);
        }
        let (value, rest) = input.split_at(n);
        input = rest;
        let alpha = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if !alpha(value[0])
            || !value.iter().all(|b| alpha(*b) || b"._-".contains(b))
            || value <= previous
        {
            return Err(Invalid);
        }
        previous = value;
    }
    if !input.is_empty() {
        return Err(Invalid);
    }
    Ok(())
}
impl CandidateHello {
    pub fn decode(bytes: &[u8]) -> Result<Self, Invalid> {
        if bytes.len() > 4096 {
            return Err(Invalid);
        }
        let fields = decode("candidate-hello", bytes, &[2, 2, 2, 3, 3, 2, 2, 1])?;
        for field in fields.iter().take(3) {
            if !matches!(field,Value::Bytes(b) if b.len()==16) {
                return Err(Invalid);
            }
        }
        let Value::Text(name) = &fields[3] else {
            return Err(Invalid);
        };
        safe_name(name)?;
        if !matches!(&fields[4],Value::Text(s) if s=="macos" || s=="windows") {
            return Err(Invalid);
        }
        let Value::Bytes(raw) = &fields[5] else {
            return Err(Invalid);
        };
        suites(raw)?;
        let Value::Bytes(fp) = &fields[6] else {
            return Err(Invalid);
        };
        let fingerprint = fp.as_slice().try_into().map_err(|_| Invalid)?;
        if !matches!(fields[7],Value::Number(n) if n>0 && n<=30_000) {
            return Err(Invalid);
        }
        let encoded = encode("candidate-hello", &fields)?;
        if encoded != bytes {
            return Err(Invalid);
        }
        Ok(Self {
            encoded,
            fingerprint,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, Invalid> {
        Ok(self.encoded.clone())
    }
}
fn connection_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
pub struct CandidateBinding {
    digest: [u8; 32],
    fingerprint: [u8; 32],
    connection_id: String,
    generation: u64,
}
impl CandidateBinding {
    pub fn select(hello: &CandidateHello, id: &str, generation: u64) -> Result<Self, Invalid> {
        if !connection_id(id) {
            return Err(Invalid);
        }
        Ok(Self {
            digest: hash(&hello.encoded),
            fingerprint: hello.fingerprint,
            connection_id: id.into(),
            generation,
        })
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn verify(&self, hello: &CandidateHello, tls: [u8; 32], id: &str, generation: u64) -> bool {
        connection_id(id)
            && self.digest == hash(&hello.encoded)
            && self.fingerprint == hello.fingerprint
            && self.fingerprint == tls
            && self.connection_id == id
            && self.generation == generation
    }
}
pub fn decode_hex32(value: &str) -> Result<[u8; 32], Invalid> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Invalid);
    }
    let mut out = [0; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| Invalid)?;
    }
    Ok(out)
}
