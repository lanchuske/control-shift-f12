use seamless_input_core::platform::{AccessState, CaptureMode, EventDisposition, PlatformInput};
#[cfg(target_os = "macos")]
use seamless_input_protocol::Button;
use seamless_input_protocol::{InputEvent, Modifier};
use std::collections::BTreeSet;

/// USB HID usage for F12. The public recovery shortcut is Control+Shift+F12.
pub const EMERGENCY_HID_USAGE: u16 = 0x45;

pub trait AccessibilityBackend {
    fn state(&self) -> AccessState;
    fn show_guidance(&mut self);
}

pub trait EventBackend {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError>;
    fn release_all(&mut self) -> Result<(), InputError>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct CaptureOutcome {
    pub disposition: EventDisposition,
    pub event: Option<InputEvent>,
    pub emergency: bool,
}

impl CaptureOutcome {
    pub fn pass_through() -> Self {
        Self {
            disposition: EventDisposition::PassThrough,
            event: None,
            emergency: false,
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum InputError {
    #[error("macOS Accessibility permission is unavailable")]
    AccessibilityUnavailable,
    #[error("CoreGraphics could not create or post the event")]
    CoreGraphics,
    #[error("unsupported input event for macOS")]
    UnsupportedEvent,
}

pub struct MacInput {
    access: Box<dyn AccessibilityBackend>,
    events: Box<dyn EventBackend>,
    guidance_shown: bool,
    last_access: AccessState,
    held: BTreeSet<Modifier>,
}

impl MacInput {
    pub fn with_backends(
        access: impl AccessibilityBackend + 'static,
        events: impl EventBackend + 'static,
    ) -> Self {
        let last_access = access.state();
        Self {
            access: Box::new(access),
            events: Box::new(events),
            guidance_shown: false,
            last_access,
            held: BTreeSet::new(),
        }
    }

    pub fn explain_permission_once(&mut self) -> bool {
        if self.access.state() == AccessState::Granted || self.guidance_shown {
            return false;
        }
        self.guidance_shown = true;
        self.access.show_guidance();
        true
    }

    pub fn capture_local(&mut self, event: InputEvent, mode: CaptureMode) -> CaptureOutcome {
        if self.access.state() != AccessState::Granted {
            return CaptureOutcome::pass_through();
        }
        if let InputEvent::Modifier { modifier, pressed } = event {
            if pressed {
                self.held.insert(modifier);
            } else {
                self.held.remove(&modifier);
            }
        }
        let emergency = matches!(
            event,
            InputEvent::Key {
                code: EMERGENCY_HID_USAGE,
                pressed: true
            }
        ) && [Modifier::Control, Modifier::Shift]
            .iter()
            .all(|modifier| self.held.contains(modifier));
        if emergency {
            let _ = self.release_all();
            return CaptureOutcome {
                disposition: EventDisposition::PassThrough,
                event: None,
                emergency: true,
            };
        }
        CaptureOutcome {
            disposition: if mode == CaptureMode::Remote {
                EventDisposition::Suppress
            } else {
                EventDisposition::PassThrough
            },
            event: Some(event),
            emergency,
        }
    }

    pub fn held_modifiers(&self) -> &BTreeSet<Modifier> {
        &self.held
    }

    pub fn refresh_access(&mut self) -> Result<(), InputError> {
        let current = self.access.state();
        if self.last_access == AccessState::Granted && current != AccessState::Granted {
            self.release_all()?;
        }
        self.last_access = current;
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), InputError> {
        self.release_all()
    }
}

impl PlatformInput for MacInput {
    type Error = InputError;
    fn access_state(&self) -> AccessState {
        self.access.state()
    }
    fn inject(&mut self, event: &InputEvent) -> Result<(), Self::Error> {
        if self.access.state() != AccessState::Granted {
            return Err(InputError::AccessibilityUnavailable);
        }
        self.events.inject(event)
    }
    fn release_all(&mut self) -> Result<(), Self::Error> {
        self.events.release_all()?;
        self.held.clear();
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use core_graphics::event::{
        CGEvent, CGEventTap, CGEventTapLocation, CGEventTapOptions, CGEventTapPlacement,
        CGEventType, CGMouseButton, CallbackResult, EventField, ScrollEventUnit,
    };
    use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
    use core_graphics::geometry::CGPoint;
    use std::sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    };

    const INJECTED_EVENT_MARKER: i64 = 0x0053_494d_4143_4f53;

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn AXIsProcessTrusted() -> bool;
    }

    #[derive(Default)]
    pub struct NativeAccessibility;
    impl AccessibilityBackend for NativeAccessibility {
        fn state(&self) -> AccessState {
            if unsafe { AXIsProcessTrusted() } {
                AccessState::Granted
            } else {
                AccessState::Denied
            }
        }
        fn show_guidance(&mut self) {
            eprintln!(
                "Control Shift F12 needs macOS Accessibility permission for mouse and keyboard sharing. Enable it in System Settings > Privacy & Security > Accessibility; pairing and topology remain available if you decline."
            );
        }
    }

    #[derive(Default)]
    pub struct CoreGraphicsEvents;
    impl CoreGraphicsEvents {
        fn source() -> Result<CGEventSource, InputError> {
            CGEventSource::new(CGEventSourceStateID::Private).map_err(|_| InputError::CoreGraphics)
        }
        fn current_location() -> Result<CGPoint, InputError> {
            Ok(CGEvent::new(Self::source()?)
                .map_err(|_| InputError::CoreGraphics)?
                .location())
        }
        fn post(event: CGEvent) {
            event.post(CGEventTapLocation::Session);
        }
    }
    impl EventBackend for CoreGraphicsEvents {
        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            let source = Self::source()?;
            let event = match event {
                InputEvent::Pointer { x, y } => CGEvent::new_mouse_event(
                    source,
                    CGEventType::MouseMoved,
                    CGPoint::new(*x, *y),
                    CGMouseButton::Left,
                ),
                InputEvent::Button { button, pressed } => {
                    let (button, down, up) = match button {
                        Button::Left => (
                            CGMouseButton::Left,
                            CGEventType::LeftMouseDown,
                            CGEventType::LeftMouseUp,
                        ),
                        Button::Right => (
                            CGMouseButton::Right,
                            CGEventType::RightMouseDown,
                            CGEventType::RightMouseUp,
                        ),
                        Button::Middle => (
                            CGMouseButton::Center,
                            CGEventType::OtherMouseDown,
                            CGEventType::OtherMouseUp,
                        ),
                        Button::Back | Button::Forward => return Err(InputError::UnsupportedEvent),
                    };
                    CGEvent::new_mouse_event(
                        source,
                        if *pressed { down } else { up },
                        Self::current_location()?,
                        button,
                    )
                }
                InputEvent::Scroll {
                    horizontal,
                    vertical,
                } => CGEvent::new_scroll_event(
                    source,
                    ScrollEventUnit::PIXEL,
                    2,
                    finite_i32(*vertical),
                    finite_i32(*horizontal),
                    0,
                ),
                InputEvent::Key { code, pressed } => CGEvent::new_keyboard_event(
                    source,
                    hid_to_keycode(*code).ok_or(InputError::UnsupportedEvent)?,
                    *pressed,
                ),
                InputEvent::Modifier { modifier, pressed } => {
                    CGEvent::new_keyboard_event(source, modifier_keycode(*modifier), *pressed)
                }
            }
            .map_err(|_| InputError::CoreGraphics)?;
            event
                .set_integer_value_field(EventField::EVENT_SOURCE_USER_DATA, INJECTED_EVENT_MARKER);
            Self::post(event);
            Ok(())
        }
        fn release_all(&mut self) -> Result<(), InputError> {
            for modifier in [
                Modifier::Shift,
                Modifier::Control,
                Modifier::Alt,
                Modifier::Meta,
            ] {
                self.inject(&InputEvent::Modifier {
                    modifier,
                    pressed: false,
                })?;
            }
            for button in [Button::Left, Button::Right, Button::Middle] {
                self.inject(&InputEvent::Button {
                    button,
                    pressed: false,
                })?;
            }
            Ok(())
        }
    }

    pub struct MacEventTap {
        _tap: CGEventTap<'static>,
        mode: Arc<AtomicU8>,
    }
    impl MacEventTap {
        pub fn install(
            mode: CaptureMode,
            callback: impl Fn(CaptureOutcome) + Send + Sync + 'static,
        ) -> Result<Self, InputError> {
            let mode_value = Arc::new(AtomicU8::new(mode as u8));
            let callback = Arc::new(callback);
            let callback_mode = Arc::clone(&mode_value);
            let emergency_mode = Arc::clone(&mode_value);
            let held = std::sync::Mutex::new(BTreeSet::new());
            let tap = CGEventTap::new(
                CGEventTapLocation::Session,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::Default,
                vec![
                    CGEventType::MouseMoved,
                    CGEventType::LeftMouseDragged,
                    CGEventType::RightMouseDragged,
                    CGEventType::LeftMouseDown,
                    CGEventType::LeftMouseUp,
                    CGEventType::RightMouseDown,
                    CGEventType::RightMouseUp,
                    CGEventType::OtherMouseDown,
                    CGEventType::OtherMouseUp,
                    CGEventType::ScrollWheel,
                    CGEventType::KeyDown,
                    CGEventType::KeyUp,
                    CGEventType::FlagsChanged,
                ],
                move |_proxy, event_type, event| {
                    if event.get_integer_value_field(EventField::EVENT_SOURCE_USER_DATA)
                        == INJECTED_EVENT_MARKER
                    {
                        return CallbackResult::Keep;
                    }
                    let input = normalize_event(event_type, event);
                    if let Ok(mut held) = held.lock() {
                        if let Some(InputEvent::Modifier { modifier, pressed }) = input.as_ref() {
                            if *pressed {
                                held.insert(*modifier);
                            } else {
                                held.remove(modifier);
                            }
                        }
                        if matches!(
                            input.as_ref(),
                            Some(InputEvent::Key {
                                code: EMERGENCY_HID_USAGE,
                                pressed: true
                            })
                        ) && [Modifier::Control, Modifier::Shift]
                            .iter()
                            .all(|modifier| held.contains(modifier))
                        {
                            held.clear();
                            emergency_mode.store(CaptureMode::Local as u8, Ordering::Relaxed);
                            callback(CaptureOutcome {
                                disposition: EventDisposition::PassThrough,
                                event: None,
                                emergency: true,
                            });
                            return CallbackResult::Keep;
                        }
                    }
                    let remote = callback_mode.load(Ordering::Relaxed) == CaptureMode::Remote as u8;
                    if let Some(input) = input {
                        callback(CaptureOutcome {
                            disposition: if remote {
                                EventDisposition::Suppress
                            } else {
                                EventDisposition::PassThrough
                            },
                            event: Some(input),
                            emergency: false,
                        });
                    }
                    if remote {
                        CallbackResult::Drop
                    } else {
                        CallbackResult::Keep
                    }
                },
            )
            .map_err(|_| InputError::AccessibilityUnavailable)?;
            let source = tap
                .mach_port()
                .create_runloop_source(0)
                .map_err(|_| InputError::CoreGraphics)?;
            core_foundation::runloop::CFRunLoop::get_current().add_source(&source, unsafe {
                core_foundation::runloop::kCFRunLoopCommonModes
            });
            tap.enable();
            Ok(Self {
                _tap: tap,
                mode: mode_value,
            })
        }
        pub fn set_mode(&self, mode: CaptureMode) {
            self.mode.store(mode as u8, Ordering::Relaxed);
        }
        /// Service pending tap callbacks without taking ownership of the
        /// application's main loop. The supervisor calls this on every tick.
        pub fn poll(&self) {
            let _ = core_foundation::runloop::CFRunLoop::run_in_mode(
                unsafe { core_foundation::runloop::kCFRunLoopDefaultMode },
                std::time::Duration::ZERO,
                true,
            );
        }
    }

    fn normalize_event(kind: CGEventType, event: &CGEvent) -> Option<InputEvent> {
        match kind {
            CGEventType::MouseMoved
            | CGEventType::LeftMouseDragged
            | CGEventType::RightMouseDragged => {
                let p = event.location();
                Some(InputEvent::Pointer { x: p.x, y: p.y })
            }
            CGEventType::LeftMouseDown | CGEventType::LeftMouseUp => Some(InputEvent::Button {
                button: Button::Left,
                pressed: matches!(kind, CGEventType::LeftMouseDown),
            }),
            CGEventType::RightMouseDown | CGEventType::RightMouseUp => Some(InputEvent::Button {
                button: Button::Right,
                pressed: matches!(kind, CGEventType::RightMouseDown),
            }),
            CGEventType::OtherMouseDown | CGEventType::OtherMouseUp => Some(InputEvent::Button {
                button: Button::Middle,
                pressed: matches!(kind, CGEventType::OtherMouseDown),
            }),
            CGEventType::ScrollWheel => Some(InputEvent::Scroll {
                horizontal: event
                    .get_double_value_field(EventField::SCROLL_WHEEL_EVENT_POINT_DELTA_AXIS_2),
                vertical: event
                    .get_double_value_field(EventField::SCROLL_WHEEL_EVENT_POINT_DELTA_AXIS_1),
            }),
            CGEventType::KeyDown | CGEventType::KeyUp => keycode_to_hid(
                event.get_integer_value_field(EventField::KEYBOARD_EVENT_KEYCODE) as u16,
            )
            .map(|code| InputEvent::Key {
                code,
                pressed: matches!(kind, CGEventType::KeyDown),
            }),
            CGEventType::FlagsChanged => modifier_for_keycode(
                event.get_integer_value_field(EventField::KEYBOARD_EVENT_KEYCODE) as u16,
            )
            .map(|modifier| InputEvent::Modifier {
                modifier,
                pressed: event.get_flags().contains(modifier_flag(modifier)),
            }),
            _ => None,
        }
    }
    fn finite_i32(value: f64) -> i32 {
        value.clamp(i32::MIN as f64, i32::MAX as f64).round() as i32
    }
    fn modifier_keycode(modifier: Modifier) -> u16 {
        match modifier {
            Modifier::Shift => 0x38,
            Modifier::Control => 0x3b,
            Modifier::Alt => 0x3a,
            Modifier::Meta => 0x37,
        }
    }
    fn modifier_for_keycode(code: u16) -> Option<Modifier> {
        match code {
            0x38 | 0x3c => Some(Modifier::Shift),
            0x3b | 0x3e => Some(Modifier::Control),
            0x3a | 0x3d => Some(Modifier::Alt),
            0x37 | 0x36 => Some(Modifier::Meta),
            _ => None,
        }
    }
    fn modifier_flag(modifier: Modifier) -> core_graphics::event::CGEventFlags {
        use core_graphics::event::CGEventFlags;
        match modifier {
            Modifier::Shift => CGEventFlags::CGEventFlagShift,
            Modifier::Control => CGEventFlags::CGEventFlagControl,
            Modifier::Alt => CGEventFlags::CGEventFlagAlternate,
            Modifier::Meta => CGEventFlags::CGEventFlagCommand,
        }
    }
    fn hid_to_keycode(code: u16) -> Option<u16> {
        const MAP: &[(u16, u16)] = &[
            (0x04, 0x00),
            (0x05, 0x0b),
            (0x06, 0x08),
            (0x07, 0x02),
            (0x08, 0x0e),
            (0x09, 0x03),
            (0x0a, 0x05),
            (0x0b, 0x04),
            (0x0c, 0x22),
            (0x0d, 0x26),
            (0x0e, 0x28),
            (0x0f, 0x25),
            (0x10, 0x2e),
            (0x11, 0x2d),
            (0x12, 0x1f),
            (0x13, 0x23),
            (0x14, 0x0c),
            (0x15, 0x0f),
            (0x16, 0x01),
            (0x17, 0x11),
            (0x18, 0x20),
            (0x19, 0x09),
            (0x1a, 0x0d),
            (0x1b, 0x07),
            (0x1c, 0x10),
            (0x1d, 0x06),
            (0x28, 0x24),
            (0x29, 0x35),
            (0x2a, 0x33),
            (0x2b, 0x30),
            (0x2c, 0x31),
            (0x4a, 0x73),
            (0x4b, 0x74),
            (0x4c, 0x75),
            (0x4d, 0x77),
            (0x4e, 0x79),
            (0x4f, 0x7c),
            (0x50, 0x7b),
            (0x51, 0x7d),
            (0x52, 0x7e),
        ];
        MAP.iter()
            .find_map(|(hid, mac)| (*hid == code).then_some(*mac))
    }
    fn keycode_to_hid(code: u16) -> Option<u16> {
        (0u16..=0xff).find(|hid| hid_to_keycode(*hid) == Some(code))
    }
}

#[cfg(target_os = "macos")]
pub use native::{CoreGraphicsEvents, MacEventTap, NativeAccessibility};

#[cfg(target_os = "macos")]
impl MacInput {
    pub fn new() -> Self {
        Self::with_backends(NativeAccessibility, CoreGraphicsEvents)
    }
}

#[cfg(target_os = "macos")]
impl Default for MacInput {
    fn default() -> Self {
        Self::new()
    }
}
