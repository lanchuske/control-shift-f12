use seamless_input_core::clipboard::{ClipboardDeduper, ClipboardError, ClipboardPayload};
use seamless_input_protocol::{MAX_PNG_BYTES, MAX_TEXT_BYTES};

fn png() -> Vec<u8> {
    // Minimal structurally valid 1x1 RGBA PNG.
    vec![
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 11, 73, 68, 65, 84, 120, 156, 99, 96, 0, 2, 0, 0, 5, 0,
        1, 122, 94, 171, 63, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ]
}

#[test]
fn accepts_bounded_text_and_png() {
    let mut d = ClipboardDeduper::new(8);
    assert!(
        d.accept_local(ClipboardPayload::text("hello"))
            .unwrap()
            .is_some()
    );
    assert!(
        d.accept_local(ClipboardPayload::png(png()))
            .unwrap()
            .is_some()
    );
}

#[test]
fn rejects_malformed_png_and_limits() {
    let mut d = ClipboardDeduper::new(8);
    assert_eq!(
        d.accept_local(ClipboardPayload::png(b"not png".to_vec())),
        Err(ClipboardError::MalformedPng)
    );
    assert_eq!(
        d.accept_local(ClipboardPayload::text("x".repeat(MAX_TEXT_BYTES + 1))),
        Err(ClipboardError::TooLarge)
    );
    assert_eq!(
        d.accept_local(ClipboardPayload::png(vec![0; MAX_PNG_BYTES + 1])),
        Err(ClipboardError::TooLarge)
    );
}

#[test]
fn dedupes_local_remote_loops_and_reconnect_replay() {
    let mut sender = ClipboardDeduper::new(2);
    let mut receiver = ClipboardDeduper::new(2);
    let transfer = sender
        .accept_local(ClipboardPayload::text("one"))
        .unwrap()
        .unwrap();
    assert!(receiver.accept_remote(transfer.clone()).unwrap().is_some());
    assert!(
        receiver
            .accept_local(ClipboardPayload::text("one"))
            .unwrap()
            .is_none()
    );
    assert!(receiver.accept_remote(transfer).unwrap().is_none());
    let two = sender
        .accept_local(ClipboardPayload::text("two"))
        .unwrap()
        .unwrap();
    let three = sender
        .accept_local(ClipboardPayload::text("three"))
        .unwrap()
        .unwrap();
    assert!(receiver.accept_remote(two).unwrap().is_some());
    assert!(receiver.accept_remote(three).unwrap().is_some());
}

#[test]
fn rejects_hash_tampering() {
    let mut d = ClipboardDeduper::new(8);
    let mut transfer = d
        .accept_local(ClipboardPayload::text("hello"))
        .unwrap()
        .unwrap();
    transfer.hash[0] ^= 1;
    assert_eq!(d.accept_remote(transfer), Err(ClipboardError::HashMismatch));
}

#[test]
fn rejects_png_with_corrupt_crc() {
    let mut bytes = png();
    bytes[33] ^= 1;
    assert_eq!(
        ClipboardDeduper::new(8).accept_local(ClipboardPayload::png(bytes)),
        Err(ClipboardError::MalformedPng)
    );
}
