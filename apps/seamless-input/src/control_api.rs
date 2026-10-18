//! Private inherited-pipe protocol. No user input is included in errors.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Read, Write};

pub const MAX_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u32,
    pub id: String,
    pub command: String,
    pub args: Value,
}

pub fn typed_request<T: Serialize>(
    id: impl Into<String>,
    command: impl Into<String>,
    args: &T,
) -> io::Result<Request> {
    let request = Request {
        v: 1,
        id: id.into(),
        command: command.into(),
        args: serde_json::to_value(args).map_err(|_| invalid())?,
    };
    validate_request(&request)?;
    Ok(request)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "control protocol: invalid frame",
    )
}

pub fn read_request(reader: &mut impl Read) -> io::Result<Option<Request>> {
    let mut prefix = [0; 4];
    // EOF between frames is normal; EOF inside a frame is a protocol error.
    loop {
        match reader.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(invalid()),
        }
    }
    reader.read_exact(&mut prefix[1..]).map_err(|_| invalid())?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(invalid());
    }
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).map_err(|_| invalid())?;
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    validate_request(&request)?;
    Ok(Some(request))
}

pub fn validate_request(request: &Request) -> io::Result<()> {
    if request.id.is_empty()
        || request.id.len() > 64
        || !request
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        || request.command.len() > 64
        || !request.args.is_object()
    {
        return Err(invalid());
    }
    Ok(())
}

pub fn write_message(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(invalid());
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}
