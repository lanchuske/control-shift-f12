//! Validated observations, not a claim of a stable display identity or physical size.
use crate::platform::LogicalDisplay;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Axes {
    pub x: f64,
    pub y: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PixelSize {
    pub width: u32,
    pub height: u32,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PhysicalSize {
    pub width: f64,
    pub height: f64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DisplayDescriptor {
    pub runtime_index: u32,
    pub stable_display_id: Option<String>,
    pub name: String,
    pub logical_bounds: Bounds,
    pub backing_scale: Axes,
    pub framebuffer_pixels: Option<PixelSize>,
    pub native_mode_pixels: Option<PixelSize>,
    pub effective_dpi: Option<Axes>,
    pub rotation_degrees: Option<u16>,
    pub physical_mm: Option<PhysicalSize>,
    pub physical_size_quality: &'static str,
    pub primary: Option<bool>,
    pub mirror_group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryError {
    InvalidGeometry,
    DuplicateDisplay,
    DisplayLimit,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DisplayInventory {
    pub generation: u64,
    digest: String,
    displays: Vec<DisplayDescriptor>,
}

impl DisplayInventory {
    pub fn from_logical(
        generation: u64,
        measured: Vec<LogicalDisplay>,
    ) -> Result<Self, InventoryError> {
        if measured.len() > 32 {
            return Err(InventoryError::DisplayLimit);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut displays = Vec::new();
        for value in measured {
            if !seen.insert(value.index) {
                return Err(InventoryError::DuplicateDisplay);
            }
            if ![
                value.origin_x,
                value.origin_y,
                value.width,
                value.height,
                value.scale,
            ]
            .iter()
            .all(|v| v.is_finite())
                || value.origin_x.abs() > 1_000_000.0
                || value.origin_y.abs() > 1_000_000.0
                || value.width <= 0.0
                || value.height <= 0.0
                || value.width > 100_000.0
                || value.height > 100_000.0
                || value.scale <= 0.0
                || value.scale > 16.0
            {
                return Err(InventoryError::InvalidGeometry);
            }
            displays.push(DisplayDescriptor {
                runtime_index: value.index,
                stable_display_id: None,
                name: format!("Display {}", value.index),
                logical_bounds: Bounds {
                    x: normalized_zero(value.origin_x),
                    y: normalized_zero(value.origin_y),
                    width: value.width,
                    height: value.height,
                },
                backing_scale: Axes {
                    x: value.scale,
                    y: value.scale,
                },
                framebuffer_pixels: None,
                native_mode_pixels: None,
                effective_dpi: None,
                rotation_degrees: None,
                physical_mm: None,
                physical_size_quality: "unavailable",
                primary: None,
                mirror_group: None,
            });
        }
        displays.sort_by_key(|d| d.runtime_index);
        // This is an inventory change fingerprint, never an authenticated layout digest.
        // Field order comes from Serialize on concrete structs; no unordered JSON maps.
        let encoded = serde_json::to_vec(&displays).map_err(|_| InventoryError::InvalidGeometry)?;
        let digest = Sha256::digest(encoded)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(Self {
            generation,
            digest,
            displays,
        })
    }
    pub fn displays(&self) -> &[DisplayDescriptor] {
        &self.displays
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn is_layout_ready(&self) -> bool {
        false
    }
}

fn normalized_zero(value: f64) -> f64 {
    if value == 0.0 { 0.0 } else { value }
}
