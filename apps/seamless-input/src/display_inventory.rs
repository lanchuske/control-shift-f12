//! Display enumeration only: never construct NativePlatform, input or clipboard.
use seamless_input_core::display_inventory::DisplayInventory;
use seamless_input_core::platform::LogicalDisplay;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use seamless_input_core::platform::PlatformDisplays;

pub fn measure(generation: u64) -> Result<DisplayInventory, &'static str> {
    let values = logical_displays()?;
    if values.is_empty() {
        return Err("no_displays");
    }
    DisplayInventory::from_logical(generation, values).map_err(|_| "invalid_display_geometry")
}

#[cfg(target_os = "macos")]
fn logical_displays() -> Result<Vec<LogicalDisplay>, &'static str> {
    seamless_input_platform_macos::MacDisplays::new()
        .displays()
        .map_err(|_| "enumeration_failed")
}
#[cfg(target_os = "windows")]
fn logical_displays() -> Result<Vec<LogicalDisplay>, &'static str> {
    seamless_input_platform_windows::WindowsDisplays::new()
        .displays()
        .map_err(|_| "enumeration_failed")
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn logical_displays() -> Result<Vec<LogicalDisplay>, &'static str> {
    Err("unsupported_platform")
}
