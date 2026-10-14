use seamless_input_protocol::*;
use std::io::{Cursor, Read};

fn sample() -> Frame {
    Frame::new(
        7,
        Message::Input(InputEvent::Key {
            code: 42,
            pressed: true,
        }),
    )
}

#[test]
fn round_trip_uses_big_endian_length_and_messagepack() {
    let bytes = encode(&sample()).unwrap();
    assert_eq!(
        u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize,
        bytes.len() - 4
    );
    assert_eq!(decode(&bytes).unwrap(), sample());
    assert_eq!(read_frame(&mut Cursor::new(bytes)).unwrap(), sample());
}

#[test]
fn truncation_is_rejected_at_every_boundary() {
    let bytes = encode(&sample()).unwrap();
    for end in 0..bytes.len() {
        assert_eq!(decode(&bytes[..end]), Err(ProtocolError::Truncated));
        assert_eq!(
            read_frame(&mut Cursor::new(&bytes[..end])),
            Err(ProtocolError::Truncated)
        );
    }
}

#[test]
fn unknown_version_is_rejected() {
    let mut frame = sample();
    frame.version = 99;
    let payload = rmp_serde::to_vec(&frame).unwrap();
    let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
    bytes.extend(payload);
    assert_eq!(decode(&bytes), Err(ProtocolError::UnknownVersion(99)));
    assert_eq!(encode(&frame), Err(ProtocolError::UnknownVersion(99)));
}

struct HeaderOnly {
    read_header: bool,
}
impl Read for HeaderOnly {
    fn read(&mut self, dest: &mut [u8]) -> std::io::Result<usize> {
        assert!(
            !self.read_header,
            "must reject oversized header before requesting payload"
        );
        self.read_header = true;
        dest[..4].copy_from_slice(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
        Ok(4)
    }
}

#[test]
fn oversized_length_is_rejected_before_payload_read() {
    assert_eq!(
        decode(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes()),
        Err(ProtocolError::TooLarge)
    );
    assert_eq!(
        read_frame(&mut HeaderOnly { read_header: false }),
        Err(ProtocolError::TooLarge)
    );
}

#[test]
fn exact_limit_is_accepted_but_serialized_overhead_counts() {
    let mut frame = Frame::new(
        0,
        Message::ClipboardChunk {
            hash: [0; 32],
            offset: 0,
            total: MAX_PNG_BYTES as u32,
            data: vec![],
        },
    );
    let overhead = rmp_serde::to_vec(&frame).unwrap().len();
    // A MessagePack bin32 length uses four bytes, three more than bin8.
    if let Message::ClipboardChunk { data, .. } = &mut frame.message {
        *data = vec![0; MAX_FRAME_BYTES - overhead - 3];
    }
    let bytes = encode(&frame).unwrap();
    assert_eq!(bytes.len(), MAX_FRAME_BYTES + 4);
    assert_eq!(decode(&bytes).unwrap(), frame);
    if let Message::ClipboardChunk { data, .. } = &mut frame.message {
        data.push(0);
    }
    assert_eq!(encode(&frame), Err(ProtocolError::TooLarge));
}

#[test]
fn trailing_or_malformed_bytes_fail_closed() {
    let mut bytes = encode(&sample()).unwrap();
    bytes.push(0);
    assert_eq!(decode(&bytes), Err(ProtocolError::Malformed));
    assert_eq!(decode(&[0, 0, 0, 1, 0xc1]), Err(ProtocolError::Malformed));
}

#[test]
fn sequence_zero_then_increasing_is_accepted() {
    let mut tracker = SequenceTracker::default();
    assert_eq!(tracker.accept(0), Ok(()));
    assert_eq!(tracker.accept(2), Ok(()));
    assert_eq!(tracker.accept(u64::MAX), Ok(()));
}

#[test]
fn duplicate_sequence_is_rejected_without_resetting_history() {
    let mut tracker = SequenceTracker::default();
    tracker.accept(4).unwrap();
    assert_eq!(tracker.accept(4), Err(ProtocolError::DuplicateSequence));
    assert_eq!(tracker.accept(5), Ok(()));
}

#[test]
fn stale_sequence_is_rejected_without_resetting_history() {
    let mut tracker = SequenceTracker::default();
    tracker.accept(8).unwrap();
    assert_eq!(tracker.accept(7), Err(ProtocolError::StaleSequence));
    assert_eq!(tracker.accept(8), Err(ProtocolError::DuplicateSequence));
    assert_eq!(tracker.accept(9), Ok(()));
}

#[test]
fn non_finite_input_coordinates_fail_closed() {
    for event in [
        InputEvent::Pointer {
            x: f64::NAN,
            y: 0.0,
        },
        InputEvent::Scroll {
            horizontal: 0.0,
            vertical: f64::INFINITY,
        },
    ] {
        let frame = Frame::new(0, Message::Input(event));
        assert_eq!(encode(&frame), Err(ProtocolError::InvalidInput));
        let payload = rmp_serde::to_vec(&frame).unwrap();
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend(payload);
        assert_eq!(decode(&bytes), Err(ProtocolError::InvalidInput));
    }
}

#[test]
fn clipboard_debug_output_does_not_disclose_content_or_hash() {
    let frame = Frame::new(
        0,
        Message::ClipboardChunk {
            hash: [123; 32],
            offset: 0,
            total: 4,
            data: vec![111, 112, 113, 114],
        },
    );
    let output = format!("{frame:?}");
    assert!(!output.contains("111") && !output.contains("123"));
}

#[test]
fn multiple_frames_are_consumed_separately_from_a_stream() {
    let first = sample();
    let second = Frame::new(8, Message::Heartbeat);
    let mut bytes = encode(&first).unwrap();
    bytes.extend(encode(&second).unwrap());
    let mut reader = Cursor::new(bytes);
    assert_eq!(read_frame(&mut reader).unwrap(), first);
    assert_eq!(read_frame(&mut reader).unwrap(), second);
    assert_eq!(read_frame(&mut reader), Err(ProtocolError::Truncated));
}

#[test]
fn declared_huge_nested_binary_length_fails_closed() {
    let frame = Frame::new(
        0,
        Message::ClipboardChunk {
            hash: [0; 32],
            offset: 0,
            total: 1,
            data: vec![42],
        },
    );
    let mut payload = rmp_serde::to_vec(&frame).unwrap();
    assert_eq!(&payload[payload.len() - 3..], &[0xc4, 1, 42]);
    payload.truncate(payload.len() - 3);
    payload.extend([0xc6, 0xff, 0xff, 0xff, 0xff]);
    let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
    bytes.extend(payload);
    assert_eq!(decode(&bytes), Err(ProtocolError::Malformed));
}
