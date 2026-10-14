//! Deterministic display topology and outgoing input control without OS access.
//!
//! Display IDs include their owner, so different peers may reuse monitor indexes.
//! Coordinates are logical desktop units; platform adapters convert physical
//! pixels using display scale. Controller actions must be executed in order,
//! while continuing local cleanup even if a remote send fails. Call `tick`
//! periodically using the same monotonic clock as crossings and heartbeats.

pub mod control;
pub mod platform;
pub mod topology;
pub use control::{Action, ControlError, Controller};
pub use seamless_input_protocol::{InputEvent, Modifier, NodeId};
pub use topology::{Display, DisplayId, Edge, Point, Topology, TopologyError};
