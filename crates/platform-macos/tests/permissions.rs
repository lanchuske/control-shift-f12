use seamless_input_core::platform::{
    AccessState, CaptureMode, ClipboardContent, ClipboardOutcome, EventDisposition, NativeDisplay,
    PlatformClipboard, PlatformDisplays, PlatformInput,
};
use seamless_input_platform_macos::{clipboard, displays, input};
use seamless_input_protocol::{InputEvent, MAX_PNG_BYTES, MAX_TEXT_BYTES, Modifier};
use std::cell::RefCell;
use std::rc::Rc;

fn png_with_dimensions(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = vec![
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 11, 73, 68, 65, 84, 120, 156, 99, 96, 0, 2, 0, 0, 5, 0,
        1, 122, 94, 171, 63, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ];
    bytes[16..20].copy_from_slice(&width.to_be_bytes());
    bytes[20..24].copy_from_slice(&height.to_be_bytes());
    let mut crc = crc32fast::Hasher::new();
    crc.update(&bytes[12..29]);
    bytes[29..33].copy_from_slice(&crc.finalize().to_be_bytes());
    bytes
}

#[derive(Clone)]
struct FakeAccess {
    state: Rc<RefCell<AccessState>>,
    prompts: Rc<RefCell<usize>>,
}

impl FakeAccess {
    fn new(state: AccessState) -> Self {
        Self {
            state: Rc::new(RefCell::new(state)),
            prompts: Rc::new(RefCell::new(0)),
        }
    }
}

impl input::AccessibilityBackend for FakeAccess {
    fn state(&self) -> AccessState {
        *self.state.borrow()
    }

    fn show_guidance(&mut self) {
        *self.prompts.borrow_mut() += 1;
    }
}

#[derive(Clone, Default)]
struct FakeEvents {
    injected: Rc<RefCell<Vec<InputEvent>>>,
    releases: Rc<RefCell<usize>>,
}

impl input::EventBackend for FakeEvents {
    fn inject(&mut self, event: &InputEvent) -> Result<(), input::InputError> {
        self.injected.borrow_mut().push(event.clone());
        Ok(())
    }

    fn release_all(&mut self) -> Result<(), input::InputError> {
        *self.releases.borrow_mut() += 1;
        Ok(())
    }
}

#[test]
fn accessibility_states_degrade_safely_and_guidance_is_one_shot() {
    for state in [AccessState::NotDetermined, AccessState::Denied] {
        let access = FakeAccess::new(state);
        let prompts = access.prompts.clone();
        let mut input = input::MacInput::with_backends(access, FakeEvents::default());
        assert_eq!(input.access_state(), state);
        assert!(input.explain_permission_once());
        assert!(!input.explain_permission_once());
        assert_eq!(*prompts.borrow(), 1);
        assert_eq!(
            input.capture_local(
                InputEvent::Key {
                    code: 4,
                    pressed: true
                },
                CaptureMode::Remote
            ),
            input::CaptureOutcome::pass_through()
        );
        assert!(matches!(
            input.inject(&InputEvent::Key {
                code: 4,
                pressed: true
            }),
            Err(input::InputError::AccessibilityUnavailable)
        ));
    }

    let mut granted = input::MacInput::with_backends(
        FakeAccess::new(AccessState::Granted),
        FakeEvents::default(),
    );
    assert_eq!(granted.access_state(), AccessState::Granted);
    assert!(!granted.explain_permission_once());
}

#[test]
fn local_events_pass_through_and_remote_events_are_suppressed() {
    let mut input = input::MacInput::with_backends(
        FakeAccess::new(AccessState::Granted),
        FakeEvents::default(),
    );
    let event = InputEvent::Pointer { x: 12.0, y: 24.0 };
    assert_eq!(
        input.capture_local(event.clone(), CaptureMode::Local),
        input::CaptureOutcome {
            disposition: EventDisposition::PassThrough,
            event: Some(event.clone()),
            emergency: false,
        }
    );
    assert_eq!(
        input.capture_local(event.clone(), CaptureMode::Remote),
        input::CaptureOutcome {
            disposition: EventDisposition::Suppress,
            event: Some(event),
            emergency: false,
        }
    );
}

#[test]
fn emergency_chord_returns_local_and_cleans_modifiers() {
    let events = FakeEvents::default();
    let releases = events.releases.clone();
    let mut input = input::MacInput::with_backends(FakeAccess::new(AccessState::Granted), events);
    for modifier in [Modifier::Control, Modifier::Alt, Modifier::Meta] {
        input.capture_local(
            InputEvent::Modifier {
                modifier,
                pressed: true,
            },
            CaptureMode::Remote,
        );
    }
    let outcome = input.capture_local(
        InputEvent::Key {
            code: 0x29,
            pressed: true,
        },
        CaptureMode::Remote,
    );
    assert!(outcome.emergency);
    assert_eq!(outcome.disposition, EventDisposition::PassThrough);
    assert_eq!(outcome.event, None);
    assert_eq!(*releases.borrow(), 1);
    assert!(input.held_modifiers().is_empty());
}

#[test]
fn permission_loss_and_shutdown_release_modifiers() {
    let access = FakeAccess::new(AccessState::Granted);
    let state = access.state.clone();
    let events = FakeEvents::default();
    let releases = events.releases.clone();
    let mut input = input::MacInput::with_backends(access, events);
    input.capture_local(
        InputEvent::Modifier {
            modifier: Modifier::Shift,
            pressed: true,
        },
        CaptureMode::Remote,
    );
    *state.borrow_mut() = AccessState::Denied;
    input.refresh_access().unwrap();
    input.shutdown().unwrap();
    assert_eq!(*releases.borrow(), 2);
    assert!(input.held_modifiers().is_empty());
}

#[derive(Clone)]
struct FakeDisplayBackend(Vec<NativeDisplay>);

impl displays::DisplayBackend for FakeDisplayBackend {
    fn active_displays(&self) -> Result<Vec<NativeDisplay>, displays::DisplayError> {
        Ok(self.0.clone())
    }
}

#[test]
fn display_pixels_are_mapped_to_logical_coordinates_by_scale() {
    let displays = displays::MacDisplays::with_backend(FakeDisplayBackend(vec![NativeDisplay {
        index: 3,
        physical_x: -3840.0,
        physical_y: 0.0,
        physical_width: 3840.0,
        physical_height: 2160.0,
        scale: 2.0,
    }]));
    let logical = displays.displays().unwrap();
    assert_eq!(logical.len(), 1);
    assert_eq!(logical[0].index, 3);
    assert_eq!(logical[0].origin_x, -1920.0);
    assert_eq!(logical[0].width, 1920.0);
    assert_eq!(logical[0].height, 1080.0);
    assert_eq!(logical[0].scale, 2.0);
}

#[derive(Clone)]
struct FakeClipboardBackend {
    consent: Rc<RefCell<AccessState>>,
    change: Rc<RefCell<u64>>,
    content: Rc<RefCell<Option<ClipboardContent>>>,
    writes: Rc<RefCell<Vec<ClipboardContent>>>,
}

impl clipboard::ClipboardBackend for FakeClipboardBackend {
    fn access_state(&self) -> AccessState {
        *self.consent.borrow()
    }
    fn change_count(&self) -> Result<u64, clipboard::ClipboardError> {
        Ok(*self.change.borrow())
    }
    fn read(&mut self) -> Result<Option<ClipboardContent>, clipboard::ClipboardError> {
        Ok(self.content.borrow().clone())
    }
    fn write(&mut self, content: &ClipboardContent) -> Result<(), clipboard::ClipboardError> {
        self.writes.borrow_mut().push(content.clone());
        Ok(())
    }
}

fn clipboard_backend(
    state: AccessState,
    content: Option<ClipboardContent>,
) -> FakeClipboardBackend {
    FakeClipboardBackend {
        consent: Rc::new(RefCell::new(state)),
        change: Rc::new(RefCell::new(1)),
        content: Rc::new(RefCell::new(content)),
        writes: Rc::new(RefCell::new(Vec::new())),
    }
}

#[test]
fn clipboard_consent_denial_disables_sync_without_error_loop() {
    let backend = clipboard_backend(
        AccessState::Denied,
        Some(ClipboardContent::Text("secret".into())),
    );
    let mut clipboard = clipboard::MacClipboard::with_backend(backend);
    assert_eq!(clipboard.poll(0).unwrap(), ClipboardOutcome::Disabled);
    assert_eq!(clipboard.poll(500).unwrap(), ClipboardOutcome::Disabled);
}

#[test]
fn clipboard_debounces_and_deduplicates_by_hash() {
    let backend = clipboard_backend(
        AccessState::Granted,
        Some(ClipboardContent::Text("hello".into())),
    );
    let change = backend.change.clone();
    let mut clipboard = clipboard::MacClipboard::with_backend(backend);
    assert_eq!(clipboard.poll(0).unwrap(), ClipboardOutcome::Pending);
    assert_eq!(clipboard.poll(199).unwrap(), ClipboardOutcome::Pending);
    assert_eq!(
        clipboard.poll(200).unwrap(),
        ClipboardOutcome::Changed(ClipboardContent::Text("hello".into()))
    );
    *change.borrow_mut() = 2;
    assert_eq!(clipboard.poll(400).unwrap(), ClipboardOutcome::Pending);
    assert_eq!(clipboard.poll(600).unwrap(), ClipboardOutcome::Unchanged);
}

#[test]
fn remote_clipboard_write_is_not_echoed_and_limits_fail_closed() {
    let backend = clipboard_backend(AccessState::Granted, None);
    let writes = backend.writes.clone();
    let content = backend.content.clone();
    let change = backend.change.clone();
    let mut clipboard = clipboard::MacClipboard::with_backend(backend);
    let remote = ClipboardContent::Text("remote".into());
    clipboard.write_remote(&remote).unwrap();
    assert_eq!(writes.borrow().as_slice(), std::slice::from_ref(&remote));
    *content.borrow_mut() = Some(remote);
    *change.borrow_mut() = 2;
    assert_eq!(clipboard.poll(0).unwrap(), ClipboardOutcome::Pending);
    assert_eq!(clipboard.poll(200).unwrap(), ClipboardOutcome::Unchanged);

    assert!(matches!(
        clipboard.write_remote(&ClipboardContent::Text("x".repeat(MAX_TEXT_BYTES + 1))),
        Err(clipboard::ClipboardError::TooLarge)
    ));
    assert!(matches!(
        clipboard.write_remote(&ClipboardContent::Png(vec![0; MAX_PNG_BYTES + 1])),
        Err(clipboard::ClipboardError::TooLarge)
    ));
    assert_eq!(
        clipboard.write_remote(&ClipboardContent::Png(png_with_dimensions(8_192, 8_192))),
        Err(clipboard::ClipboardError::TooLarge)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn native_non_admin_permission_and_display_probe_is_safe() {
    let input = input::MacInput::new();
    assert!(matches!(
        input.access_state(),
        AccessState::Granted | AccessState::Denied
    ));
    let displays = displays::MacDisplays::new().displays().unwrap();
    assert!(!displays.is_empty());
    assert!(
        displays
            .iter()
            .all(|display| display.width > 0.0 && display.height > 0.0)
    );
}
