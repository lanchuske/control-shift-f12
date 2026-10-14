use seamless_input_core::platform::{LogicalDisplay, NativeDisplay, PlatformDisplays};

pub trait DisplayBackend {
    fn active_displays(&self) -> Result<Vec<NativeDisplay>, DisplayError>;
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DisplayError {
    #[error("Windows could not enumerate active displays")]
    Enumeration,
    #[error("display geometry or scale is invalid")]
    InvalidGeometry,
}

pub struct WindowsDisplays {
    backend: Box<dyn DisplayBackend>,
}

impl WindowsDisplays {
    pub fn with_backend(backend: impl DisplayBackend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }
}

impl PlatformDisplays for WindowsDisplays {
    type Error = DisplayError;

    fn displays(&self) -> Result<Vec<LogicalDisplay>, Self::Error> {
        self.backend
            .active_displays()?
            .into_iter()
            .map(|display| {
                if !display.physical_x.is_finite()
                    || !display.physical_y.is_finite()
                    || !display.physical_width.is_finite()
                    || !display.physical_height.is_finite()
                    || !display.scale.is_finite()
                    || display.physical_width <= 0.0
                    || display.physical_height <= 0.0
                    || display.scale <= 0.0
                {
                    return Err(DisplayError::InvalidGeometry);
                }
                Ok(LogicalDisplay {
                    index: display.index,
                    origin_x: display.physical_x / display.scale,
                    origin_y: display.physical_y / display.scale,
                    width: display.physical_width / display.scale,
                    height: display.physical_height / display.scale,
                    scale: display.scale,
                })
            })
            .collect()
    }
}

#[cfg(target_os = "windows")]
mod native {
    use super::*;
    use std::sync::Mutex;
    use windows_sys::Win32::{
        Foundation::{LPARAM, RECT},
        Graphics::Gdi::{EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO},
        UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI},
    };

    static ENUMERATED: Mutex<Vec<NativeDisplay>> = Mutex::new(Vec::new());

    unsafe extern "system" fn monitor_callback(
        monitor: HMONITOR,
        _hdc: HDC,
        _rect: *mut RECT,
        _data: LPARAM,
    ) -> i32 {
        let mut info: MONITORINFO = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        if unsafe { GetMonitorInfoW(monitor, &mut info) } == 0 {
            return 1;
        }
        let mut dpi_x = 96u32;
        let mut dpi_y = 96u32;
        let _ = unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y) };
        let rect = info.rcMonitor;
        if let Ok(mut displays) = ENUMERATED.lock() {
            let index = displays.len() as u32;
            displays.push(NativeDisplay {
                index,
                physical_x: f64::from(rect.left),
                physical_y: f64::from(rect.top),
                physical_width: f64::from(rect.right - rect.left),
                physical_height: f64::from(rect.bottom - rect.top),
                scale: f64::from(dpi_x) / 96.0,
            });
        }
        1
    }

    #[derive(Default)]
    pub struct Win32Displays;
    impl DisplayBackend for Win32Displays {
        fn active_displays(&self) -> Result<Vec<NativeDisplay>, DisplayError> {
            let mut guard = ENUMERATED.lock().map_err(|_| DisplayError::Enumeration)?;
            guard.clear();
            drop(guard);
            if unsafe {
                EnumDisplayMonitors(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    Some(monitor_callback),
                    0,
                )
            } == 0
            {
                return Err(DisplayError::Enumeration);
            }
            let mut guard = ENUMERATED.lock().map_err(|_| DisplayError::Enumeration)?;
            if guard.is_empty() {
                return Err(DisplayError::Enumeration);
            }
            Ok(std::mem::take(&mut *guard))
        }
    }
}

#[cfg(target_os = "windows")]
pub use native::Win32Displays;

#[cfg(target_os = "windows")]
impl WindowsDisplays {
    pub fn new() -> Self {
        Self::with_backend(Win32Displays)
    }
}

#[cfg(target_os = "windows")]
impl Default for WindowsDisplays {
    fn default() -> Self {
        Self::new()
    }
}
