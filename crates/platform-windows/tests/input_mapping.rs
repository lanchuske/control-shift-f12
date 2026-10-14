use seamless_input_core::platform::{
    AccessState, CaptureMode, ClipboardContent, ClipboardOutcome, EventDisposition, NativeDisplay,
    PlatformClipboard, PlatformDisplays, PlatformInput,
};
use seamless_input_platform_windows::{clipboard, displays, input};
use seamless_input_protocol::{Button, InputEvent, MAX_PNG_BYTES, MAX_TEXT_BYTES, Modifier};
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
struct FakeSession {
    state: Rc<RefCell<input::DesktopState>>,
}

impl input::SessionBackend for FakeSession {
    fn desktop_state(&self) -> input::DesktopState {
        *self.state.borrow()
    }
}

#[derive(Clone, Default)]
struct FakeEvents {
    injected: Rc<RefCell<Vec<input::NativeInput>>>,
}

impl input::EventBackend for FakeEvents {
    fn send(&mut self, events: &[input::NativeInput]) -> Result<(), input::InputError> {
        self.injected.borrow_mut().extend_from_slice(events);
        Ok(())
    }
}

fn windows_input(
    desktop: input::DesktopState,
) -> (input::WindowsInput, Rc<RefCell<Vec<input::NativeInput>>>) {
    let events = FakeEvents::default();
    let injected = events.injected.clone();
    let input = input::WindowsInput::with_backends(
        FakeSession {
            state: Rc::new(RefCell::new(desktop)),
        },
        events,
    );
    (input, injected)
}

#[test]
fn hooks_pass_local_input_and_suppress_only_while_remote() {
    let (mut input, _) = windows_input(input::DesktopState::Interactive);
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
fn secure_or_elevated_desktop_refuses_capture_and_injection() {
    for state in [input::DesktopState::Secure, input::DesktopState::Elevated] {
        let (mut input, injected) = windows_input(state);
        assert_eq!(input.access_state(), AccessState::Denied);
        assert_eq!(
            input.capture_local(
                InputEvent::Key {
                    code: 4,
                    pressed: true
                },
                CaptureMode::Remote,
            ),
            input::CaptureOutcome::pass_through()
        );
        assert_eq!(
            input.inject(&InputEvent::Key {
                code: 4,
                pressed: true
            }),
            Err(input::InputError::DesktopUnavailable)
        );
        assert!(injected.borrow().is_empty());
    }
}

#[test]
fn leaving_interactive_desktop_releases_held_input() {
    let state = Rc::new(RefCell::new(input::DesktopState::Interactive));
    let events = FakeEvents::default();
    let injected = events.injected.clone();
    let mut input = input::WindowsInput::with_backends(
        FakeSession {
            state: state.clone(),
        },
        events,
    );
    input.capture_local(
        InputEvent::Modifier {
            modifier: Modifier::Shift,
            pressed: true,
        },
        CaptureMode::Remote,
    );
    input.capture_local(
        InputEvent::Button {
            button: Button::Left,
            pressed: true,
        },
        CaptureMode::Remote,
    );
    *state.borrow_mut() = input::DesktopState::Secure;
    input.refresh_session().unwrap();
    assert!(input.held_modifiers().is_empty());
    assert!(input.held_buttons().is_empty());
    assert_eq!(injected.borrow().len(), 9);
}

#[test]
fn absolute_pointer_is_normalized_over_virtual_desktop() {
    let desktop = input::VirtualDesktop {
        left: -1920,
        top: -200,
        width: 4480,
        height: 1640,
    };
    assert_eq!(
        input::normalize_absolute(-1920.0, -200.0, desktop).unwrap(),
        (0, 0)
    );
    assert_eq!(
        input::normalize_absolute(2559.0, 1439.0, desktop).unwrap(),
        (65_535, 65_535)
    );
    assert_eq!(
        input::normalize_absolute(320.0, 620.0, desktop).unwrap(),
        (32_775, 32_787)
    );
    assert_eq!(
        input::normalize_absolute(f64::NAN, 0.0, desktop),
        Err(input::InputError::InvalidCoordinate)
    );
}

#[test]
fn buttons_wheel_and_hid_scancodes_map_without_layout_translation() {
    assert_eq!(
        input::map_event(&InputEvent::Button {
            button: Button::Forward,
            pressed: true
        })
        .unwrap(),
        vec![input::NativeInput::Button {
            button: Button::Forward,
            pressed: true
        }]
    );
    assert_eq!(
        input::map_event(&InputEvent::Scroll {
            horizontal: -1.5,
            vertical: 2.25
        })
        .unwrap(),
        vec![input::NativeInput::Wheel {
            horizontal: -180,
            vertical: 270
        }]
    );
    assert_eq!(
        input::map_event(&InputEvent::Key {
            code: 4,
            pressed: true
        })
        .unwrap(),
        vec![input::NativeInput::ScanCode {
            code: 0x1e,
            extended: false,
            pressed: true
        }]
    );
    assert_eq!(
        input::map_event(&InputEvent::Key {
            code: 0x4f,
            pressed: false
        })
        .unwrap(),
        vec![input::NativeInput::ScanCode {
            code: 0x4d,
            extended: true,
            pressed: false
        }]
    );
    assert_eq!(
        input::map_event(&InputEvent::Key {
            code: 0xffff,
            pressed: true
        }),
        Err(input::InputError::UnsupportedHidUsage(0xffff))
    );
}

#[test]
fn physical_scancodes_are_layout_independent() {
    assert_eq!(input::hid_to_scancode(0x14), Some((0x10, false))); // physical Q key
    assert_eq!(input::hid_to_scancode(0x1d), Some((0x2c, false))); // physical Z key
    assert_eq!(input::hid_to_scancode(0xe6), Some((0x38, true))); // right Alt / AltGr
}

#[test]
fn low_level_hook_records_physical_keys_and_ignores_our_injected_events() {
    assert_eq!(
        input::map_keyboard_hook(input::HookKeyboardEvent {
            scan_code: 0x1e,
            extended: false,
            pressed: true,
            injected: false,
        }),
        Some(InputEvent::Key {
            code: 0x04,
            pressed: true
        })
    );
    assert_eq!(
        input::map_keyboard_hook(input::HookKeyboardEvent {
            scan_code: 0x1e,
            extended: false,
            pressed: true,
            injected: true,
        }),
        None
    );
    assert_eq!(
        input::map_keyboard_hook(input::HookKeyboardEvent {
            scan_code: 0x38,
            extended: true,
            pressed: false,
            injected: false,
        }),
        Some(InputEvent::Modifier {
            modifier: Modifier::Alt,
            pressed: false
        })
    );
}

#[test]
fn low_level_mouse_hook_maps_buttons_wheel_and_pointer() {
    assert_eq!(
        input::map_mouse_hook(input::HookMouseEvent::Pointer {
            x: -40,
            y: 10,
            injected: false
        }),
        Some(InputEvent::Pointer { x: -40.0, y: 10.0 })
    );
    assert_eq!(
        input::map_mouse_hook(input::HookMouseEvent::Wheel {
            horizontal: true,
            delta: -240,
            injected: false
        }),
        Some(InputEvent::Scroll {
            horizontal: -2.0,
            vertical: 0.0
        })
    );
    assert_eq!(
        input::map_mouse_hook(input::HookMouseEvent::Button {
            button: Button::Back,
            pressed: true,
            injected: false
        }),
        Some(InputEvent::Button {
            button: Button::Back,
            pressed: true
        })
    );
    assert_eq!(
        input::map_mouse_hook(input::HookMouseEvent::Pointer {
            x: 0,
            y: 0,
            injected: true
        }),
        None
    );
}

#[test]
fn emergency_chord_returns_local_and_releases_held_state() {
    let (mut input, injected) = windows_input(input::DesktopState::Interactive);
    for modifier in [Modifier::Control, Modifier::Alt, Modifier::Meta] {
        input.capture_local(
            InputEvent::Modifier {
                modifier,
                pressed: true,
            },
            CaptureMode::Remote,
        );
    }
    input.capture_local(
        InputEvent::Button {
            button: Button::Left,
            pressed: true,
        },
        CaptureMode::Remote,
    );
    let outcome = input.capture_local(
        InputEvent::Key {
            code: input::EMERGENCY_HID_USAGE,
            pressed: true,
        },
        CaptureMode::Remote,
    );
    assert!(outcome.emergency);
    assert_eq!(outcome.disposition, EventDisposition::PassThrough);
    assert_eq!(outcome.event, None);
    assert!(input.held_modifiers().is_empty());
    assert!(input.held_buttons().is_empty());
    let sent = injected.borrow();
    assert!(sent.contains(&input::NativeInput::Modifier {
        modifier: Modifier::Control,
        pressed: false
    }));
    assert!(sent.contains(&input::NativeInput::Button {
        button: Button::Left,
        pressed: false
    }));
}

#[test]
fn shutdown_releases_every_modifier_and_button() {
    let (mut input, injected) = windows_input(input::DesktopState::Interactive);
    input.shutdown().unwrap();
    let sent = injected.borrow();
    assert_eq!(sent.len(), 9);
    assert!(sent.iter().all(|event| match event {
        input::NativeInput::Modifier { pressed, .. }
        | input::NativeInput::Button { pressed, .. } => !pressed,
        _ => false,
    }));
}

#[derive(Clone)]
struct FakeDisplayBackend(Vec<NativeDisplay>);

impl displays::DisplayBackend for FakeDisplayBackend {
    fn active_displays(&self) -> Result<Vec<NativeDisplay>, displays::DisplayError> {
        Ok(self.0.clone())
    }
}

#[test]
fn display_pixels_map_to_logical_coordinates_with_negative_origins() {
    let displays =
        displays::WindowsDisplays::with_backend(FakeDisplayBackend(vec![NativeDisplay {
            index: 2,
            physical_x: -3840.0,
            physical_y: -400.0,
            physical_width: 3840.0,
            physical_height: 2160.0,
            scale: 2.0,
        }]));
    let logical = displays.displays().unwrap();
    assert_eq!(logical[0].origin_x, -1920.0);
    assert_eq!(logical[0].origin_y, -200.0);
    assert_eq!(logical[0].width, 1920.0);
    assert_eq!(logical[0].height, 1080.0);
}

#[derive(Clone)]
struct FakeClipboardBackend {
    sequence: Rc<RefCell<u64>>,
    content: Rc<RefCell<Option<ClipboardContent>>>,
    writes: Rc<RefCell<Vec<ClipboardContent>>>,
    available: Rc<RefCell<bool>>,
}

impl clipboard::ClipboardBackend for FakeClipboardBackend {
    fn available(&self) -> bool {
        *self.available.borrow()
    }
    fn sequence_number(&self) -> Result<u64, clipboard::ClipboardError> {
        Ok(*self.sequence.borrow())
    }
    fn read(&mut self) -> Result<Option<ClipboardContent>, clipboard::ClipboardError> {
        Ok(self.content.borrow().clone())
    }
    fn write(&mut self, content: &ClipboardContent) -> Result<(), clipboard::ClipboardError> {
        self.writes.borrow_mut().push(content.clone());
        Ok(())
    }
}

fn clipboard_backend(content: Option<ClipboardContent>) -> FakeClipboardBackend {
    FakeClipboardBackend {
        sequence: Rc::new(RefCell::new(1)),
        content: Rc::new(RefCell::new(content)),
        writes: Rc::new(RefCell::new(Vec::new())),
        available: Rc::new(RefCell::new(true)),
    }
}

#[test]
fn clipboard_debounces_deduplicates_and_enforces_bounds() {
    let backend = clipboard_backend(Some(ClipboardContent::Text("hello".into())));
    let sequence = backend.sequence.clone();
    let mut clipboard = clipboard::WindowsClipboard::with_backend(backend);
    assert_eq!(clipboard.poll(0).unwrap(), ClipboardOutcome::Pending);
    assert_eq!(clipboard.poll(199).unwrap(), ClipboardOutcome::Pending);
    assert_eq!(
        clipboard.poll(200).unwrap(),
        ClipboardOutcome::Changed(ClipboardContent::Text("hello".into()))
    );
    *sequence.borrow_mut() = 2;
    assert_eq!(clipboard.poll(400).unwrap(), ClipboardOutcome::Pending);
    assert_eq!(clipboard.poll(600).unwrap(), ClipboardOutcome::Unchanged);
    assert_eq!(
        clipboard.write_remote(&ClipboardContent::Text("x".repeat(MAX_TEXT_BYTES + 1))),
        Err(clipboard::ClipboardError::TooLarge)
    );
    assert_eq!(
        clipboard.write_remote(&ClipboardContent::Png(vec![0; MAX_PNG_BYTES + 1])),
        Err(clipboard::ClipboardError::TooLarge)
    );
    assert_eq!(
        clipboard.write_remote(&ClipboardContent::Png(png_with_dimensions(8_192, 8_192))),
        Err(clipboard::ClipboardError::TooLarge)
    );
}

#[test]
fn remote_clipboard_write_is_not_echoed() {
    let backend = clipboard_backend(None);
    let content = backend.content.clone();
    let sequence = backend.sequence.clone();
    let writes = backend.writes.clone();
    let mut clipboard = clipboard::WindowsClipboard::with_backend(backend);
    let remote = ClipboardContent::Png(png_with_dimensions(1, 1));
    clipboard.write_remote(&remote).unwrap();
    assert_eq!(writes.borrow().as_slice(), std::slice::from_ref(&remote));
    *content.borrow_mut() = Some(remote);
    *sequence.borrow_mut() = 2;
    assert_eq!(clipboard.poll(0).unwrap(), ClipboardOutcome::Pending);
    assert_eq!(clipboard.poll(200).unwrap(), ClipboardOutcome::Unchanged);
}
