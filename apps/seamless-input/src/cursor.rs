use seamless_input_core::{Display, DisplayId, Point, platform::LogicalDisplay};

/// Convert a Windows hook's physical virtual-desktop coordinate to the
/// logical coordinate space shared by topology and the remote protocol.
pub fn physical_to_logical(native: Point, displays: &[LogicalDisplay]) -> Option<Point> {
    if !native.x.is_finite() || !native.y.is_finite() {
        return None;
    }
    displays.iter().find_map(|display| {
        let left = display.origin_x * display.scale;
        let top = display.origin_y * display.scale;
        let right = left + display.width * display.scale;
        let bottom = top + display.height * display.scale;
        (native.x >= left && native.x < right && native.y >= top && native.y < bottom).then_some(
            Point {
                x: native.x / display.scale,
                y: native.y / display.scale,
            },
        )
    })
}

pub fn logical_to_physical(logical: Point, displays: &[LogicalDisplay]) -> Option<Point> {
    if !logical.x.is_finite() || !logical.y.is_finite() {
        return None;
    }
    displays.iter().find_map(|display| {
        let right = display.origin_x + display.width;
        let bottom = display.origin_y + display.height;
        (logical.x >= display.origin_x
            && logical.x < right
            && logical.y >= display.origin_y
            && logical.y < bottom)
            .then_some(Point {
                x: logical.x * display.scale,
                y: logical.y * display.scale,
            })
    })
}

/// Converts the absolute coordinates emitted by native hooks into a logical
/// cursor that can continue moving while the native cursor is suppressed at a
/// local edge. All coordinates passed here are already in logical units.
#[derive(Debug, Clone)]
pub struct CursorContinuity {
    local: seamless_input_core::NodeId,
    last_native: Option<Point>,
    logical: Option<Point>,
}

impl CursorContinuity {
    pub fn new(local: DisplayId) -> Self {
        Self {
            local: local.node,
            last_native: None,
            logical: None,
        }
    }

    pub fn observe(&mut self, native: Point, active: &Display) -> Point {
        let previous = self.last_native.replace(native);
        if active.id.node == self.local {
            self.logical = Some(native);
            return native;
        }
        let mut logical = self.logical.unwrap_or(Point {
            x: active.origin.x + active.width / 2.0,
            y: active.origin.y + active.height / 2.0,
        });
        if let Some(previous) = previous {
            logical.x += native.x - previous.x;
            logical.y += native.y - previous.y;
        }
        self.logical = Some(logical);
        logical
    }

    pub fn warp(&mut self, _display: DisplayId, point: Point) {
        self.logical = Some(point);
    }
}
