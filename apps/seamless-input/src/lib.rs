//! Shared application surfaces used by the CLI and its integration tests.

pub mod config;
pub mod control_api;
pub mod control_engine;
pub mod cursor;
pub mod diagnostics;
pub mod display_inventory;
#[cfg(feature = "pairing-v2-g4")]
pub mod guided_setup;
pub mod peer;
#[cfg(feature = "pairing-v2-g4")]
pub mod product_pairing_adapter;
pub mod runtime;
pub mod runtime_status;
pub mod supervisor;
pub mod tui;
pub mod ui_contract;
pub mod ui_controller;
pub mod ui_projection;
pub mod ui_stdio_adapter;
