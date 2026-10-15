use seamless_input_core::platform::{LogicalDisplay, NativeDisplay, PlatformDisplays};

pub trait DisplayBackend {
    fn active_displays(&self) -> Result<Vec<NativeDisplay>, DisplayError>;
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DisplayError {
    #[error("CoreGraphics could not enumerate active displays")]
    Enumeration,
    #[error("display geometry or scale is invalid")]
    InvalidGeometry,
}

pub struct MacDisplays {
    backend: Box<dyn DisplayBackend>,
}

impl MacDisplays {
    pub fn with_backend(backend: impl DisplayBackend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }
}

impl PlatformDisplays for MacDisplays {
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

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use core_graphics::display::CGDisplay;

    #[derive(Default)]
    pub struct CoreGraphicsDisplays;

    impl DisplayBackend for CoreGraphicsDisplays {
        fn active_displays(&self) -> Result<Vec<NativeDisplay>, DisplayError> {
            CGDisplay::active_displays()
                .map_err(|_| DisplayError::Enumeration)?
                .into_iter()
                .map(|id| {
                    let display = CGDisplay::new(id);
                    let bounds = display.bounds();
                    let width = display.pixels_wide() as f64;
                    let height = display.pixels_high() as f64;
                    let scale = width / bounds.size.width;
                    if !scale.is_finite() || scale <= 0.0 {
                        return Err(DisplayError::InvalidGeometry);
                    }
                    Ok(NativeDisplay {
                        index: id,
                        physical_x: bounds.origin.x * scale,
                        physical_y: bounds.origin.y * scale,
                        physical_width: width,
                        physical_height: height,
                        scale,
                    })
                })
                .collect()
        }
    }
}

#[cfg(target_os = "macos")]
pub use native::CoreGraphicsDisplays;

#[cfg(target_os = "macos")]
impl MacDisplays {
    pub fn new() -> Self {
        Self::with_backend(CoreGraphicsDisplays)
    }
}

#[cfg(target_os = "macos")]
impl Default for MacDisplays {
    fn default() -> Self {
        Self::new()
    }
}
