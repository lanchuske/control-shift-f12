use crate::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DisplayId {
    pub node: NodeId,
    pub index: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Display {
    pub id: DisplayId,
    pub origin: Point,
    pub width: f64,
    pub height: f64,
    pub scale: f64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Edge {
    Left,
    Right,
    Top,
    Bottom,
}
impl Edge {
    pub fn opposite(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
            Self::Top => Self::Bottom,
            Self::Bottom => Self::Top,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyError {
    InvalidDisplay,
    UnknownDisplay,
    Collision,
    DuplicateDisplay,
    InvalidPoint,
    Disconnected,
}
#[derive(Debug, Clone)]
pub struct Topology {
    tiles: std::collections::BTreeMap<DisplayId, (Display, (i32, i32))>,
}
impl Topology {
    pub fn new(root: Display) -> Result<Self, TopologyError> {
        root.validate()?;
        Ok(Self {
            tiles: std::collections::BTreeMap::from([(root.id, (root, (0, 0)))]),
        })
    }

    /// Place or move a tile beside an existing tile. Placement is atomic;
    /// neighbors are derived from occupied cardinal grid cells, so reciprocity
    /// and cycle closure cannot diverge. Display rectangles are peer-local
    /// logical desktop coordinates; tile grid cells represent TUI adjacency.
    pub fn place(
        &mut self,
        anchor: DisplayId,
        edge: Edge,
        display: Display,
    ) -> Result<(), TopologyError> {
        display.validate()?;
        if anchor == display.id {
            return Err(TopologyError::DuplicateDisplay);
        }
        let position = self.position(anchor).ok_or(TopologyError::UnknownDisplay)?;
        let destination = adjacent(position, edge).ok_or(TopologyError::InvalidDisplay)?;
        if self
            .tiles
            .iter()
            .any(|(id, (_, pos))| *id != display.id && *pos == destination)
        {
            return Err(TopologyError::Collision);
        }
        let mut candidate = self.clone();
        candidate.tiles.insert(display.id, (display, destination));
        let mut seen = std::collections::BTreeSet::new();
        let mut pending = vec![anchor];
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            for edge in [Edge::Left, Edge::Right, Edge::Top, Edge::Bottom] {
                if let Some(neighbor) = candidate.neighbor(id, edge) {
                    pending.push(neighbor);
                }
            }
        }
        if seen.len() != candidate.tiles.len() {
            return Err(TopologyError::Disconnected);
        }
        *self = candidate;
        Ok(())
    }
    pub fn neighbor(&self, display: DisplayId, edge: Edge) -> Option<DisplayId> {
        let destination = adjacent(self.position(display)?, edge)?;
        self.tiles
            .iter()
            .find_map(|(id, (_, pos))| (*pos == destination).then_some(*id))
    }
    pub fn display(&self, id: DisplayId) -> Option<&Display> {
        self.tiles.get(&id).map(|(display, _)| display)
    }
    pub fn displays(&self) -> Vec<&Display> {
        self.tiles.values().map(|(display, _)| display).collect()
    }
    pub fn position(&self, id: DisplayId) -> Option<(i32, i32)> {
        self.tiles.get(&id).map(|(_, position)| *position)
    }

    pub fn map_crossing(
        &self,
        source: DisplayId,
        edge: Edge,
        point: Point,
    ) -> Result<Option<(DisplayId, Point)>, TopologyError> {
        if !point.x.is_finite() || !point.y.is_finite() {
            return Err(TopologyError::InvalidPoint);
        }
        let source = self.display(source).ok_or(TopologyError::UnknownDisplay)?;
        let on_edge = match edge {
            Edge::Left => point.x <= source.origin.x,
            Edge::Right => point.x >= source.origin.x + source.width,
            Edge::Top => point.y <= source.origin.y,
            Edge::Bottom => point.y >= source.origin.y + source.height,
        };
        if !on_edge {
            return Ok(None);
        }
        let orthogonal_valid = match edge {
            Edge::Left | Edge::Right => {
                point.y >= source.origin.y && point.y <= source.origin.y + source.height
            }
            Edge::Top | Edge::Bottom => {
                point.x >= source.origin.x && point.x <= source.origin.x + source.width
            }
        };
        if !orthogonal_valid {
            return Err(TopologyError::InvalidPoint);
        }
        let Some(target_id) = self.neighbor(source.id, edge) else {
            return Ok(None);
        };
        let target = self
            .display(target_id)
            .ok_or(TopologyError::UnknownDisplay)?;
        let horizontal = matches!(edge, Edge::Left | Edge::Right);
        let fraction = if horizontal {
            (point.y - source.origin.y) / source.height
        } else {
            (point.x - source.origin.x) / source.width
        }
        .clamp(0.0, 1.0);
        let mapped = match edge {
            Edge::Left => Point {
                x: (target.origin.x + target.width).next_down(),
                y: inside(target.origin.y, target.height, fraction),
            },
            Edge::Right => Point {
                x: target.origin.x,
                y: inside(target.origin.y, target.height, fraction),
            },
            Edge::Top => Point {
                x: inside(target.origin.x, target.width, fraction),
                y: (target.origin.y + target.height).next_down(),
            },
            Edge::Bottom => Point {
                x: inside(target.origin.x, target.width, fraction),
                y: target.origin.y,
            },
        };
        Ok(Some((target_id, mapped)))
    }
}

impl Display {
    /// Width, height, and origin are logical coordinates. Adapters perform
    /// physical-pixel conversion using scale before entering this pure API.
    pub fn validate(&self) -> Result<(), TopologyError> {
        if !self.origin.x.is_finite()
            || !self.origin.y.is_finite()
            || !self.width.is_finite()
            || !self.height.is_finite()
            || !self.scale.is_finite()
            || self.width <= 0.0
            || self.height <= 0.0
            || self.scale <= 0.0
            || !(self.origin.x + self.width).is_finite()
            || !(self.origin.y + self.height).is_finite()
            || self.origin.x + self.width <= self.origin.x
            || self.origin.y + self.height <= self.origin.y
        {
            return Err(TopologyError::InvalidDisplay);
        }
        Ok(())
    }
}

fn inside(origin: f64, extent: f64, fraction: f64) -> f64 {
    (origin + extent * fraction)
        .min((origin + extent).next_down())
        .max(origin)
}
fn adjacent((x, y): (i32, i32), edge: Edge) -> Option<(i32, i32)> {
    match edge {
        Edge::Left => Some((x.checked_sub(1)?, y)),
        Edge::Right => Some((x.checked_add(1)?, y)),
        Edge::Top => Some((x, y.checked_sub(1)?)),
        Edge::Bottom => Some((x, y.checked_add(1)?)),
    }
}
impl std::fmt::Display for TopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TopologyError {}
