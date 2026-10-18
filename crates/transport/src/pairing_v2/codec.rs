use super::Invalid;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Number(u64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
}
pub const MAX_FRAME: usize = 16_384;
pub fn encode(kind: &str, values: &[Value]) -> Result<Vec<u8>, Invalid> {
    if !kind.is_ascii() || kind.len() > 255 || values.len() > 64 {
        return Err(Invalid);
    }
    let mut out = b"CSF12E01".to_vec();
    out.push(kind.len() as u8);
    out.extend(kind.as_bytes());
    out.extend((values.len() as u16).to_be_bytes());
    for (index, value) in values.iter().enumerate() {
        let (ty, body) = match value {
            Value::Number(n) => (1, n.to_be_bytes().to_vec()),
            Value::Bytes(b) => (2, b.clone()),
            Value::Text(s) => (3, s.as_bytes().to_vec()),
            Value::Bool(b) => (4, vec![u8::from(*b)]),
        };
        if body.len() > MAX_FRAME || out.len() + 7 + body.len() > MAX_FRAME {
            return Err(Invalid);
        }
        out.extend(((index + 1) as u16).to_be_bytes());
        out.push(ty);
        out.extend((body.len() as u32).to_be_bytes());
        out.extend(body);
    }
    Ok(out)
}
pub fn decode(kind: &str, bytes: &[u8], types: &[u8]) -> Result<Vec<Value>, Invalid> {
    if bytes.len() > MAX_FRAME || !kind.is_ascii() || kind.len() > 255 || types.len() > 64 {
        return Err(Invalid);
    }
    let mut input = bytes;
    fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], Invalid> {
        if n > input.len() {
            return Err(Invalid);
        }
        let (a, b) = input.split_at(n);
        *input = b;
        Ok(a)
    }
    if take(&mut input, 8)? != b"CSF12E01" {
        return Err(Invalid);
    }
    let length = take(&mut input, 1)?[0] as usize;
    if take(&mut input, length)? != kind.as_bytes() {
        return Err(Invalid);
    }
    let count = u16::from_be_bytes(take(&mut input, 2)?.try_into().map_err(|_| Invalid)?) as usize;
    if count != types.len() {
        return Err(Invalid);
    }
    let mut values = Vec::with_capacity(count);
    for (index, expected_type) in types.iter().enumerate() {
        let tag = u16::from_be_bytes(take(&mut input, 2)?.try_into().map_err(|_| Invalid)?);
        let ty = take(&mut input, 1)?[0];
        if tag as usize != index + 1 || ty != *expected_type {
            return Err(Invalid);
        }
        let len =
            u32::from_be_bytes(take(&mut input, 4)?.try_into().map_err(|_| Invalid)?) as usize;
        let body = take(&mut input, len)?;
        values.push(match ty {
            1 if len == 8 => {
                Value::Number(u64::from_be_bytes(body.try_into().map_err(|_| Invalid)?))
            }
            2 => Value::Bytes(body.to_vec()),
            3 => Value::Text(std::str::from_utf8(body).map_err(|_| Invalid)?.to_owned()),
            4 if body == [0] || body == [1] => Value::Bool(body[0] == 1),
            _ => return Err(Invalid),
        });
    }
    if !input.is_empty() {
        return Err(Invalid);
    }
    Ok(values)
}
