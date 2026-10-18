//! Internal bounded wire grammar and fail-stop ordering; no authentication capability.
use super::{
    CandidateHello, Invalid,
    operational_wire::{CandidateRequest, FrameKind, TransportFrame},
};
#[cfg(test)]
mod tests;
pub(super) const APPLICATION_ERROR: u32 = 0x43534612;
pub(super) const SCHEDULE: [(u8, u8); 17] = [
    (1, 1),
    (1, 2),
    (2, 1),
    (2, 2),
    (3, 1),
    (3, 2),
    (4, 1),
    (4, 2),
    (5, 1),
    (5, 2),
    (6, 1),
    (6, 2),
    (7, 1),
    (8, 2),
    (9, 1),
    (10, 1),
    (10, 2),
];
pub(super) struct Envelope {
    pub kind: u8,
    pub direction: u8,
    pub sequence: u32,
    pub payload: Vec<u8>,
}
impl Envelope {
    pub fn decode(raw: &[u8]) -> Result<Self, Invalid> {
        if raw.len() < 20
            || raw.len() > 16404
            || &raw[..8] != b"CSF12H2\0"
            || raw[8..10] != 2u16.to_be_bytes()
        {
            return Err(Invalid);
        }
        let kind = raw[10];
        let direction = raw[11];
        let sequence = u32::from_be_bytes(raw[12..16].try_into().map_err(|_| Invalid)?);
        let len = u32::from_be_bytes(raw[16..20].try_into().map_err(|_| Invalid)?) as usize;
        if !(1..=11).contains(&kind)
            || !(1..=2).contains(&direction)
            || len == 0
            || len > 16384
            || raw.len() != 20 + len
        {
            return Err(Invalid);
        }
        Ok(Self {
            kind,
            direction,
            sequence,
            payload: raw[20..].to_vec(),
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, Invalid> {
        if !(1..=11).contains(&self.kind)
            || !(1..=2).contains(&self.direction)
            || self.payload.is_empty()
            || self.payload.len() > 16384
        {
            return Err(Invalid);
        }
        let mut out = b"CSF12H2\0".to_vec();
        out.extend(2u16.to_be_bytes());
        out.extend([self.kind, self.direction]);
        out.extend(self.sequence.to_be_bytes());
        out.extend((self.payload.len() as u32).to_be_bytes());
        out.extend(&self.payload);
        Ok(out)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Status {
    Active,
    FcVerified,
    CompletePendingAuthority,
    Cancelled,
    Aborted,
}
pub(super) struct WireGuard {
    status: Status,
    next: usize,
    closed: [bool; 2],
}
impl WireGuard {
    pub fn new() -> Self {
        Self {
            status: Status::Active,
            next: 0,
            closed: [false; 2],
        }
    }
    pub fn protocol_error(&mut self) -> bool {
        self.status = Status::Aborted;
        false
    }
    pub fn receive_bytes(
        &mut self,
        raw: &[u8],
        mut validate: impl FnMut(usize, &Envelope) -> bool,
    ) -> bool {
        if matches!(self.status, Status::Cancelled | Status::Aborted) {
            return false;
        }
        if self.status != Status::Active {
            return self.protocol_error();
        }
        let Ok(envelope) = Envelope::decode(raw) else {
            return self.protocol_error();
        };
        if envelope.sequence as usize != self.next {
            return self.protocol_error();
        }
        if envelope.kind == 11 {
            if self.next < 8 || !validate(self.next, &envelope) {
                return self.protocol_error();
            }
            self.status = Status::Cancelled;
            return true;
        }
        if SCHEDULE.get(self.next) != Some(&(envelope.kind, envelope.direction))
            || !validate(self.next, &envelope)
        {
            return self.protocol_error();
        }
        self.next += 1;
        if self.next == 17 {
            self.status = Status::FcVerified;
        }
        true
    }
    pub fn half_close(&mut self, role: u8) -> bool {
        if matches!(self.status, Status::Cancelled | Status::Aborted) {
            return false;
        }
        if self.status != Status::FcVerified
            || !(1..=2).contains(&role)
            || self.closed[usize::from(role - 1)]
        {
            return self.protocol_error();
        }
        self.closed[usize::from(role - 1)] = true;
        if self.closed == [true, true] {
            self.status = Status::CompletePendingAuthority;
        }
        true
    }
    pub fn status(&self) -> Status {
        self.status
    }
    #[cfg(test)]
    pub fn protocol_failed(&self) -> bool {
        self.status == Status::Aborted
    }
    pub fn sequence(&self) -> usize {
        self.next
    }
}
pub(super) struct CandidateGuard {
    next: usize,
    aborted: bool,
}
impl CandidateGuard {
    pub fn new() -> Self {
        Self {
            next: 0,
            aborted: false,
        }
    }
    pub fn protocol_error(&mut self) -> bool {
        self.aborted = true;
        false
    }
    pub fn receive(
        &mut self,
        kind: u8,
        requester: u8,
        responder: u8,
        raw: &[u8],
        mut validate: impl FnMut(usize, &[u8]) -> bool,
    ) -> bool {
        const SCHEDULE: [(u8, u8, u8); 6] = [
            (1, 1, 1),
            (2, 1, 2),
            (3, 1, 2),
            (1, 2, 2),
            (2, 2, 1),
            (3, 2, 1),
        ];
        if self.aborted {
            return false;
        }
        if SCHEDULE.get(self.next) != Some(&(kind, requester, responder)) {
            return self.protocol_error();
        }
        if kind == 3 {
            if !raw.is_empty() {
                return self.protocol_error();
            }
        } else {
            let Ok(frame) = TransportFrame::decode(raw) else {
                return self.protocol_error();
            };
            let valid = match (kind, frame.kind) {
                (1, FrameKind::CandidateRequest) => {
                    CandidateRequest::decode(&frame.payload).is_ok()
                }
                (2, FrameKind::CandidateHello) => CandidateHello::decode(&frame.payload).is_ok(),
                _ => false,
            };
            if !valid || !validate(self.next, raw) {
                return self.protocol_error();
            }
        }
        self.next += 1;
        true
    }
    #[cfg(test)]
    pub fn protocol_failed(&self) -> bool {
        self.aborted
    }
    pub fn complete(&self) -> bool {
        !self.aborted && self.next == 6
    }
}
