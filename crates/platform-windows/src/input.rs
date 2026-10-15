use seamless_input_core::platform::{AccessState, CaptureMode, EventDisposition, PlatformInput};
use seamless_input_protocol::{Button, InputEvent, Modifier};
use std::collections::BTreeSet;

pub const EMERGENCY_HID_USAGE: u16 = 0x29;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopState {
    Interactive,
    Secure,
    Elevated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualDesktop {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

pub trait SessionBackend {
    fn desktop_state(&self) -> DesktopState;
    fn virtual_desktop(&self) -> Result<VirtualDesktop, InputError> {
        Ok(VirtualDesktop {
            left: 0,
            top: 0,
            width: 65_536,
            height: 65_536,
        })
    }
}

pub trait EventBackend {
    fn send(&mut self, events: &[NativeInput]) -> Result<(), InputError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeInput {
    AbsolutePointer {
        x: u16,
        y: u16,
    },
    Button {
        button: Button,
        pressed: bool,
    },
    Wheel {
        horizontal: i32,
        vertical: i32,
    },
    ScanCode {
        code: u16,
        extended: bool,
        pressed: bool,
    },
    Modifier {
        modifier: Modifier,
        pressed: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookKeyboardEvent {
    pub scan_code: u16,
    pub extended: bool,
    pub pressed: bool,
    pub injected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookMouseEvent {
    Pointer {
        x: i32,
        y: i32,
        injected: bool,
    },
    Button {
        button: Button,
        pressed: bool,
        injected: bool,
    },
    Wheel {
        horizontal: bool,
        delta: i16,
        injected: bool,
    },
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
    #[error("Windows interactive desktop is unavailable")]
    DesktopUnavailable,
    #[error("input coordinate or virtual desktop is invalid")]
    InvalidCoordinate,
    #[error("unsupported USB HID keyboard usage {0:#06x}")]
    UnsupportedHidUsage(u16),
    #[error("Windows rejected synthesized input")]
    InjectionBlocked,
    #[error("Windows input backend failed")]
    Backend,
}

pub struct WindowsInput {
    session: Box<dyn SessionBackend>,
    events: Box<dyn EventBackend>,
    last_desktop: DesktopState,
    held_modifiers: BTreeSet<Modifier>,
    held_buttons: Vec<Button>,
}

impl WindowsInput {
    pub fn with_backends(
        session: impl SessionBackend + 'static,
        events: impl EventBackend + 'static,
    ) -> Self {
        let last_desktop = session.desktop_state();
        Self {
            session: Box::new(session),
            events: Box::new(events),
            last_desktop,
            held_modifiers: BTreeSet::new(),
            held_buttons: Vec::new(),
        }
    }

    pub fn capture_local(&mut self, event: InputEvent, mode: CaptureMode) -> CaptureOutcome {
        if self.session.desktop_state() != DesktopState::Interactive {
            return CaptureOutcome::pass_through();
        }
        match event {
            InputEvent::Modifier { modifier, pressed } => {
                if pressed {
                    self.held_modifiers.insert(modifier);
                } else {
                    self.held_modifiers.remove(&modifier);
                }
            }
            InputEvent::Button { button, pressed } => {
                if pressed && !self.held_buttons.contains(&button) {
                    self.held_buttons.push(button);
                } else if !pressed {
                    self.held_buttons.retain(|held| *held != button);
                }
            }
            _ => {}
        }
        let emergency = matches!(
            event,
            InputEvent::Key {
                code: EMERGENCY_HID_USAGE,
                pressed: true
            }
        ) && [Modifier::Control, Modifier::Alt, Modifier::Meta]
            .iter()
            .all(|modifier| self.held_modifiers.contains(modifier));
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
        &self.held_modifiers
    }
    pub fn held_buttons(&self) -> &[Button] {
        &self.held_buttons
    }
    pub fn refresh_session(&mut self) -> Result<(), InputError> {
        let current = self.session.desktop_state();
        if self.last_desktop == DesktopState::Interactive && current != DesktopState::Interactive {
            self.release_all()?;
        }
        self.last_desktop = current;
        Ok(())
    }
    pub fn shutdown(&mut self) -> Result<(), InputError> {
        self.release_all()
    }
}

impl PlatformInput for WindowsInput {
    type Error = InputError;

    fn access_state(&self) -> AccessState {
        if self.session.desktop_state() == DesktopState::Interactive {
            AccessState::Granted
        } else {
            AccessState::Denied
        }
    }

    fn inject(&mut self, event: &InputEvent) -> Result<(), Self::Error> {
        if self.session.desktop_state() != DesktopState::Interactive {
            return Err(InputError::DesktopUnavailable);
        }
        let mapped = match event {
            InputEvent::Pointer { x, y } => {
                let (x, y) = normalize_absolute(*x, *y, self.session.virtual_desktop()?)?;
                vec![NativeInput::AbsolutePointer { x, y }]
            }
            _ => map_event(event)?,
        };
        self.events.send(&mapped)
    }

    fn release_all(&mut self) -> Result<(), Self::Error> {
        let mut releases = Vec::with_capacity(9);
        for modifier in [
            Modifier::Shift,
            Modifier::Control,
            Modifier::Alt,
            Modifier::Meta,
        ] {
            releases.push(NativeInput::Modifier {
                modifier,
                pressed: false,
            });
        }
        for button in [
            Button::Left,
            Button::Right,
            Button::Middle,
            Button::Back,
            Button::Forward,
        ] {
            releases.push(NativeInput::Button {
                button,
                pressed: false,
            });
        }
        self.events.send(&releases)?;
        self.held_modifiers.clear();
        self.held_buttons.clear();
        Ok(())
    }
}

pub fn normalize_absolute(
    x: f64,
    y: f64,
    desktop: VirtualDesktop,
) -> Result<(u16, u16), InputError> {
    if !x.is_finite() || !y.is_finite() || desktop.width <= 1 || desktop.height <= 1 {
        return Err(InputError::InvalidCoordinate);
    }
    let normalized = |value: f64, origin: i32, extent: i32| {
        (((value - f64::from(origin)) / f64::from(extent - 1)) * 65_535.0)
            .round()
            .clamp(0.0, 65_535.0) as u16
    };
    Ok((
        normalized(x, desktop.left, desktop.width),
        normalized(y, desktop.top, desktop.height),
    ))
}

pub fn map_event(event: &InputEvent) -> Result<Vec<NativeInput>, InputError> {
    match *event {
        InputEvent::Pointer { .. } => Err(InputError::InvalidCoordinate),
        InputEvent::Button { button, pressed } => Ok(vec![NativeInput::Button { button, pressed }]),
        InputEvent::Scroll {
            horizontal,
            vertical,
        } if horizontal.is_finite() && vertical.is_finite() => Ok(vec![NativeInput::Wheel {
            horizontal: (horizontal * 120.0)
                .round()
                .clamp(i32::MIN as f64, i32::MAX as f64) as i32,
            vertical: (vertical * 120.0)
                .round()
                .clamp(i32::MIN as f64, i32::MAX as f64) as i32,
        }]),
        InputEvent::Scroll { .. } => Err(InputError::InvalidCoordinate),
        InputEvent::Key { code, pressed } => {
            let (code, extended) =
                hid_to_scancode(code).ok_or(InputError::UnsupportedHidUsage(code))?;
            Ok(vec![NativeInput::ScanCode {
                code,
                extended,
                pressed,
            }])
        }
        InputEvent::Modifier { modifier, pressed } => {
            Ok(vec![NativeInput::Modifier { modifier, pressed }])
        }
    }
}

pub fn map_keyboard_hook(event: HookKeyboardEvent) -> Option<InputEvent> {
    if event.injected {
        return None;
    }
    let usage = scancode_to_hid(event.scan_code, event.extended)?;
    let modifier = match usage {
        0xe0 | 0xe4 => Some(Modifier::Control),
        0xe1 | 0xe5 => Some(Modifier::Shift),
        0xe2 | 0xe6 => Some(Modifier::Alt),
        0xe3 | 0xe7 => Some(Modifier::Meta),
        _ => None,
    };
    Some(match modifier {
        Some(modifier) => InputEvent::Modifier {
            modifier,
            pressed: event.pressed,
        },
        None => InputEvent::Key {
            code: usage,
            pressed: event.pressed,
        },
    })
}

pub fn map_mouse_hook(event: HookMouseEvent) -> Option<InputEvent> {
    match event {
        HookMouseEvent::Pointer { injected: true, .. }
        | HookMouseEvent::Button { injected: true, .. }
        | HookMouseEvent::Wheel { injected: true, .. } => None,
        HookMouseEvent::Pointer { x, y, .. } => Some(InputEvent::Pointer {
            x: f64::from(x),
            y: f64::from(y),
        }),
        HookMouseEvent::Button {
            button, pressed, ..
        } => Some(InputEvent::Button { button, pressed }),
        HookMouseEvent::Wheel {
            horizontal, delta, ..
        } => {
            let amount = f64::from(delta) / 120.0;
            Some(InputEvent::Scroll {
                horizontal: if horizontal { amount } else { 0.0 },
                vertical: if horizontal { 0.0 } else { amount },
            })
        }
    }
}

fn scancode_to_hid(scan_code: u16, extended: bool) -> Option<u16> {
    (0u16..=0xe7).find(|usage| hid_to_scancode(*usage) == Some((scan_code, extended)))
}

pub fn hid_to_scancode(usage: u16) -> Option<(u16, bool)> {
    let result = match usage {
        0x04..=0x1d => {
            const LETTERS: [u16; 26] = [
                0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31,
                0x18, 0x19, 0x10, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c,
            ];
            (LETTERS[(usage - 0x04) as usize], false)
        }
        0x1e..=0x26 => (
            [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a][(usage - 0x1e) as usize],
            false,
        ),
        0x27 => (0x0b, false),
        0x28 => (0x1c, false),
        0x29 => (0x01, false),
        0x2a => (0x0e, false),
        0x2b => (0x0f, false),
        0x2c => (0x39, false),
        0x2d => (0x0c, false),
        0x2e => (0x0d, false),
        0x2f => (0x1a, false),
        0x30 => (0x1b, false),
        0x31 => (0x2b, false),
        0x33 => (0x27, false),
        0x34 => (0x28, false),
        0x35 => (0x29, false),
        0x36 => (0x33, false),
        0x37 => (0x34, false),
        0x38 => (0x35, false),
        0x39 => (0x3a, false),
        0x3a..=0x43 => (0x3b + usage - 0x3a, false),
        0x4a => (0x47, true),
        0x4b => (0x49, true),
        0x4c => (0x53, true),
        0x4d => (0x4f, true),
        0x4e => (0x51, true),
        0x4f => (0x4d, true),
        0x50 => (0x4b, true),
        0x51 => (0x50, true),
        0x52 => (0x48, true),
        0xe0 => (0x1d, false),
        0xe1 => (0x2a, false),
        0xe2 => (0x38, false),
        0xe3 => (0x5b, true),
        0xe4 => (0x1d, true),
        0xe5 => (0x36, false),
        0xe6 => (0x38, true),
        0xe7 => (0x5c, true),
        _ => return None,
    };
    Some(result)
}

#[cfg(target_os = "windows")]
mod native {
    use super::*;
    use std::{
        mem::size_of,
        sync::{
            Arc, Mutex, OnceLock,
            atomic::{AtomicBool, Ordering},
            mpsc::{self, Receiver, Sender},
        },
        thread::{self, JoinHandle},
    };
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, HC_ACTION, KBDLLHOOKSTRUCT, LLKHF_EXTENDED, LLKHF_INJECTED,
        LLMHF_INJECTED, MSG, MSLLHOOKSTRUCT, PM_NOREMOVE, PeekMessageW, PostThreadMessageW,
        SetWindowsHookExW, UnhookWindowsHookEx, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN, WM_KEYUP,
        WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE,
        WM_MOUSEWHEEL, WM_QUIT, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
        WM_XBUTTONDOWN, WM_XBUTTONUP,
    };
    use windows_sys::Win32::UI::{
        Input::KeyboardAndMouse::{
            INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
            KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL,
            MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP,
            MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK,
            MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, SendInput,
        },
        WindowsAndMessaging::{
            GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
            SM_YVIRTUALSCREEN,
        },
    };

    struct HookSink {
        sender: Sender<CaptureOutcome>,
        remote: Arc<AtomicBool>,
        held_modifiers: BTreeSet<Modifier>,
    }
    static HOOK_SINK: OnceLock<Mutex<Option<HookSink>>> = OnceLock::new();

    pub struct WindowsHooks {
        thread_id: u32,
        worker: Option<JoinHandle<()>>,
        remote: Arc<AtomicBool>,
    }

    impl WindowsHooks {
        pub fn install() -> Result<(Self, Receiver<CaptureOutcome>), InputError> {
            let sink = HOOK_SINK.get_or_init(|| Mutex::new(None));
            let mut guard = sink.lock().map_err(|_| InputError::Backend)?;
            if guard.is_some() {
                return Err(InputError::Backend);
            }
            let (sender, receiver) = mpsc::channel();
            let remote = Arc::new(AtomicBool::new(false));
            *guard = Some(HookSink {
                sender,
                remote: remote.clone(),
                held_modifiers: BTreeSet::new(),
            });
            drop(guard);
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let worker = thread::Builder::new()
                .name("seamless-input-win32-hooks".into())
                .spawn(move || hook_thread(ready_tx))
                .map_err(|_| {
                    clear_sink();
                    InputError::Backend
                })?;
            let thread_id = match ready_rx.recv() {
                Ok(Ok(thread_id)) => thread_id,
                _ => {
                    let _ = worker.join();
                    clear_sink();
                    return Err(InputError::Backend);
                }
            };
            Ok((
                Self {
                    thread_id,
                    worker: Some(worker),
                    remote,
                },
                receiver,
            ))
        }

        pub fn set_remote_capture(&self, remote: bool) {
            self.remote.store(remote, Ordering::Release);
        }
    }

    impl Drop for WindowsHooks {
        fn drop(&mut self) {
            self.remote.store(false, Ordering::Release);
            unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0) };
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            clear_sink();
        }
    }

    fn hook_thread(ready: mpsc::SyncSender<Result<u32, InputError>>) {
        let mut message: MSG = unsafe { std::mem::zeroed() };
        // Force creation of this thread's message queue before exposing its ID.
        unsafe { PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_NOREMOVE) };
        let keyboard = unsafe {
            SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), std::ptr::null_mut(), 0)
        };
        if keyboard.is_null() {
            let _ = ready.send(Err(InputError::Backend));
            return;
        }
        let mouse =
            unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook), std::ptr::null_mut(), 0) };
        if mouse.is_null() {
            unsafe { UnhookWindowsHookEx(keyboard) };
            let _ = ready.send(Err(InputError::Backend));
            return;
        }
        let _ = ready.send(Ok(unsafe { GetCurrentThreadId() }));
        while unsafe { GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) } > 0 {}
        unsafe {
            UnhookWindowsHookEx(keyboard);
            UnhookWindowsHookEx(mouse);
        }
    }

    fn clear_sink() {
        if let Some(sink) = HOOK_SINK.get()
            && let Ok(mut guard) = sink.lock()
        {
            *guard = None;
        }
    }

    fn emit(event: Option<InputEvent>) -> bool {
        let Some(event) = event else {
            return false;
        };
        let Some(sink) = HOOK_SINK.get() else {
            return false;
        };
        let Ok(mut guard) = sink.lock() else {
            return false;
        };
        let Some(sink) = guard.as_mut() else {
            return false;
        };
        if let InputEvent::Modifier { modifier, pressed } = &event {
            if *pressed {
                sink.held_modifiers.insert(*modifier);
            } else {
                sink.held_modifiers.remove(modifier);
            }
        }
        let emergency = matches!(
            event,
            InputEvent::Key {
                code: EMERGENCY_HID_USAGE,
                pressed: true
            }
        ) && [Modifier::Control, Modifier::Alt, Modifier::Meta]
            .iter()
            .all(|modifier| sink.held_modifiers.contains(modifier));
        if emergency {
            sink.held_modifiers.clear();
            sink.remote.store(false, Ordering::Release);
            let _ = sink.sender.send(CaptureOutcome {
                disposition: EventDisposition::PassThrough,
                event: None,
                emergency: true,
            });
            return false;
        }
        let remote = sink.remote.load(Ordering::Acquire);
        let _ = sink.sender.send(CaptureOutcome {
            disposition: if remote {
                EventDisposition::Suppress
            } else {
                EventDisposition::PassThrough
            },
            event: Some(event),
            emergency: false,
        });
        remote
    }

    unsafe extern "system" fn keyboard_hook(code: i32, wparam: usize, lparam: isize) -> isize {
        if code == HC_ACTION as i32 {
            let raw = unsafe { &*(lparam as *const KBDLLHOOKSTRUCT) };
            let pressed = matches!(wparam as u32, WM_KEYDOWN | WM_SYSKEYDOWN);
            let released = matches!(wparam as u32, WM_KEYUP | WM_SYSKEYUP);
            if (pressed || released)
                && emit(map_keyboard_hook(HookKeyboardEvent {
                    scan_code: raw.scanCode as u16,
                    extended: raw.flags & LLKHF_EXTENDED != 0,
                    pressed,
                    injected: raw.flags & LLKHF_INJECTED != 0,
                }))
            {
                return 1;
            }
        }
        unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
    }

    unsafe extern "system" fn mouse_hook(code: i32, wparam: usize, lparam: isize) -> isize {
        if code == HC_ACTION as i32 {
            let raw = unsafe { &*(lparam as *const MSLLHOOKSTRUCT) };
            let injected = raw.flags & LLMHF_INJECTED != 0;
            let event = match wparam as u32 {
                WM_MOUSEMOVE => Some(HookMouseEvent::Pointer {
                    x: raw.pt.x,
                    y: raw.pt.y,
                    injected,
                }),
                WM_LBUTTONDOWN => Some(HookMouseEvent::Button {
                    button: Button::Left,
                    pressed: true,
                    injected,
                }),
                WM_LBUTTONUP => Some(HookMouseEvent::Button {
                    button: Button::Left,
                    pressed: false,
                    injected,
                }),
                WM_RBUTTONDOWN => Some(HookMouseEvent::Button {
                    button: Button::Right,
                    pressed: true,
                    injected,
                }),
                WM_RBUTTONUP => Some(HookMouseEvent::Button {
                    button: Button::Right,
                    pressed: false,
                    injected,
                }),
                WM_MBUTTONDOWN => Some(HookMouseEvent::Button {
                    button: Button::Middle,
                    pressed: true,
                    injected,
                }),
                WM_MBUTTONUP => Some(HookMouseEvent::Button {
                    button: Button::Middle,
                    pressed: false,
                    injected,
                }),
                WM_XBUTTONDOWN | WM_XBUTTONUP => Some(HookMouseEvent::Button {
                    button: if (raw.mouseData >> 16) as u16 == 1 {
                        Button::Back
                    } else {
                        Button::Forward
                    },
                    pressed: wparam as u32 == WM_XBUTTONDOWN,
                    injected,
                }),
                WM_MOUSEWHEEL | WM_MOUSEHWHEEL => Some(HookMouseEvent::Wheel {
                    horizontal: wparam as u32 == WM_MOUSEHWHEEL,
                    delta: (raw.mouseData >> 16) as u16 as i16,
                    injected,
                }),
                _ => None,
            };
            if emit(event.and_then(map_mouse_hook)) {
                return 1;
            }
        }
        unsafe { CallNextHookEx(std::ptr::null_mut(), code, wparam, lparam) }
    }

    #[derive(Default)]
    pub struct WindowsSession;
    impl SessionBackend for WindowsSession {
        fn desktop_state(&self) -> DesktopState {
            use windows_sys::Win32::System::StationsAndDesktops::{
                CloseDesktop, DESKTOP_READOBJECTS, GetUserObjectInformationW, OpenInputDesktop,
                UOI_NAME,
            };
            let desktop = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
            if desktop.is_null() {
                return DesktopState::Secure;
            }
            let mut name = [0u16; 64];
            let mut needed = 0u32;
            let ok = unsafe {
                GetUserObjectInformationW(
                    desktop,
                    UOI_NAME,
                    name.as_mut_ptr().cast(),
                    (name.len() * size_of::<u16>()) as u32,
                    &mut needed,
                )
            };
            unsafe { CloseDesktop(desktop) };
            if ok == 0 {
                return DesktopState::Secure;
            }
            let end = name
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(name.len());
            let name = String::from_utf16_lossy(&name[..end]);
            if name.eq_ignore_ascii_case("default") {
                DesktopState::Interactive
            } else {
                DesktopState::Secure
            }
        }
        fn virtual_desktop(&self) -> Result<VirtualDesktop, InputError> {
            let desktop = VirtualDesktop {
                left: unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) },
                top: unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) },
                width: unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) },
                height: unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) },
            };
            if desktop.width <= 1 || desktop.height <= 1 {
                Err(InputError::InvalidCoordinate)
            } else {
                Ok(desktop)
            }
        }
    }

    #[derive(Default)]
    pub struct SendInputBackend;
    impl EventBackend for SendInputBackend {
        fn send(&mut self, events: &[NativeInput]) -> Result<(), InputError> {
            let mut native = Vec::with_capacity(events.len());
            for event in events {
                match *event {
                    NativeInput::Wheel {
                        horizontal,
                        vertical,
                    } => {
                        if vertical != 0 {
                            native.push(mouse_input(0, 0, vertical as u32, MOUSEEVENTF_WHEEL));
                        }
                        if horizontal != 0 {
                            native.push(mouse_input(0, 0, horizontal as u32, MOUSEEVENTF_HWHEEL));
                        }
                    }
                    event => native.push(to_windows_input(event)),
                }
            }
            if native.is_empty() {
                return Ok(());
            }
            let sent = unsafe {
                SendInput(
                    native.len() as u32,
                    native.as_ptr(),
                    size_of::<INPUT>() as i32,
                )
            };
            if sent as usize != native.len() {
                return Err(InputError::InjectionBlocked);
            }
            Ok(())
        }
    }

    fn to_windows_input(event: NativeInput) -> INPUT {
        match event {
            NativeInput::AbsolutePointer { x, y } => mouse_input(
                i32::from(x),
                i32::from(y),
                0,
                MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            ),
            NativeInput::Wheel {
                horizontal,
                vertical,
            } => {
                if vertical != 0 {
                    mouse_input(0, 0, vertical as u32, MOUSEEVENTF_WHEEL)
                } else {
                    mouse_input(0, 0, horizontal as u32, MOUSEEVENTF_HWHEEL)
                }
            }
            NativeInput::Button { button, pressed } => {
                let (data, flags) = match (button, pressed) {
                    (Button::Left, true) => (0, MOUSEEVENTF_LEFTDOWN),
                    (Button::Left, false) => (0, MOUSEEVENTF_LEFTUP),
                    (Button::Right, true) => (0, MOUSEEVENTF_RIGHTDOWN),
                    (Button::Right, false) => (0, MOUSEEVENTF_RIGHTUP),
                    (Button::Middle, true) => (0, MOUSEEVENTF_MIDDLEDOWN),
                    (Button::Middle, false) => (0, MOUSEEVENTF_MIDDLEUP),
                    (Button::Back, true) => (1, MOUSEEVENTF_XDOWN),
                    (Button::Back, false) => (1, MOUSEEVENTF_XUP),
                    (Button::Forward, true) => (2, MOUSEEVENTF_XDOWN),
                    (Button::Forward, false) => (2, MOUSEEVENTF_XUP),
                };
                mouse_input(0, 0, data, flags)
            }
            NativeInput::ScanCode {
                code,
                extended,
                pressed,
            } => key_input(code, extended, pressed),
            NativeInput::Modifier { modifier, pressed } => {
                let (code, extended) = match modifier {
                    Modifier::Shift => (0x2a, false),
                    Modifier::Control => (0x1d, false),
                    Modifier::Alt => (0x38, false),
                    Modifier::Meta => (0x5b, true),
                };
                key_input(code, extended, pressed)
            }
        }
    }

    fn mouse_input(x: i32, y: i32, data: u32, flags: u32) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: x,
                    dy: y,
                    mouseData: data,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }
    fn key_input(code: u16, extended: bool, pressed: bool) -> INPUT {
        let mut flags = KEYEVENTF_SCANCODE;
        if extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        if !pressed {
            flags |= KEYEVENTF_KEYUP;
        }
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: 0,
                    wScan: code,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }
}

#[cfg(target_os = "windows")]
pub use native::{SendInputBackend, WindowsHooks, WindowsSession};

#[cfg(target_os = "windows")]
impl WindowsInput {
    pub fn new() -> Self {
        Self::with_backends(WindowsSession, SendInputBackend)
    }
}

#[cfg(target_os = "windows")]
impl Default for WindowsInput {
    fn default() -> Self {
        Self::new()
    }
}
