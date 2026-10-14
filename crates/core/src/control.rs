use crate::{DisplayId, Edge, InputEvent, Modifier, NodeId, Point, Topology};
use std::collections::BTreeSet;
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Local(InputEvent),
    Send {
        target: NodeId,
        event: InputEvent,
    },
    ReleaseAll {
        target: NodeId,
    },
    Warp {
        target: NodeId,
        display: DisplayId,
        point: Point,
    },
    TargetChanged {
        target: NodeId,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    InvalidLocalDisplay,
    InvalidTimeout,
    InvalidInput,
    ClockWentBackwards,
    Topology,
    Stopped,
    Timeout,
}
#[derive(Debug)]
pub struct Controller {
    topology: Topology,
    local: DisplayId,
    active: DisplayId,
    held: BTreeSet<Modifier>,
    timeout_ms: u64,
    last_now: u64,
    remote_alive_at: Option<u64>,
    input_available: bool,
    stopped: bool,
}
impl Controller {
    /// Pure outgoing-input router. The runtime must authenticate sessions,
    /// enforce the incoming exclusive lease, and execute these actions in order.
    /// A failed remote send must never prevent subsequent local cleanup.
    /// Time values come from one monotonic millisecond clock, never wall time.
    pub fn new(
        topology: Topology,
        local: DisplayId,
        timeout_ms: u64,
    ) -> Result<Self, ControlError> {
        if topology.display(local).is_none() {
            return Err(ControlError::InvalidLocalDisplay);
        }
        if timeout_ms == 0 {
            return Err(ControlError::InvalidTimeout);
        }
        Ok(Self {
            topology,
            local,
            active: local,
            held: BTreeSet::new(),
            timeout_ms,
            last_now: 0,
            remote_alive_at: None,
            input_available: true,
            stopped: false,
        })
    }
    pub fn active_target(&self) -> NodeId {
        self.active.node
    }
    pub fn active_display(&self) -> DisplayId {
        self.active
    }
    pub fn route(&mut self, event: InputEvent) -> Result<Vec<Action>, ControlError> {
        if self.stopped {
            return Err(ControlError::Stopped);
        }
        if !event.is_valid() {
            return Err(ControlError::InvalidInput);
        }
        if let InputEvent::Modifier { modifier, pressed } = &event {
            if *pressed {
                self.held.insert(*modifier);
            } else {
                self.held.remove(modifier);
            }
        }
        Ok(vec![self.routed(event)])
    }
    fn routed(&self, event: InputEvent) -> Action {
        if self.active.node == self.local.node {
            Action::Local(event)
        } else {
            Action::Send {
                target: self.active.node,
                event,
            }
        }
    }
    fn check_time(&mut self, now_ms: u64) -> Result<(), ControlError> {
        if now_ms < self.last_now {
            return Err(ControlError::ClockWentBackwards);
        }
        self.last_now = now_ms;
        Ok(())
    }
    pub fn cross(
        &mut self,
        edge: Edge,
        point: Point,
        now_ms: u64,
    ) -> Result<Vec<Action>, ControlError> {
        if self.stopped {
            return Err(ControlError::Stopped);
        }
        self.check_time(now_ms)?;
        if self.expired(now_ms) {
            return Ok(self.emergency_return());
        }
        if !self.input_available {
            return Ok(vec![]);
        }
        let Some((display, point)) = self
            .topology
            .map_crossing(self.active, edge, point)
            .map_err(|_| ControlError::Topology)?
        else {
            return Ok(vec![]);
        };
        let previous = self.active.node;
        self.active = display;
        let mut actions = vec![];
        if previous != display.node {
            actions.push(Action::ReleaseAll { target: previous });
            actions.push(Action::TargetChanged {
                target: display.node,
            });
            self.remote_alive_at = (display.node != self.local.node).then_some(now_ms);
        }
        actions.push(Action::Warp {
            target: display.node,
            display,
            point,
        });
        if previous != display.node {
            for modifier in &self.held {
                actions.push(self.routed(InputEvent::Modifier {
                    modifier: *modifier,
                    pressed: true,
                }));
            }
        }
        Ok(actions)
    }
    /// An emergency must work even when the current remote session is dead.
    /// ReleaseAll is emitted for both endpoints; adapters release every held
    /// modifier, key and button. No remote acknowledgement is needed to return.
    pub fn emergency_return(&mut self) -> Vec<Action> {
        let previous = self.active.node;
        let mut actions = vec![Action::ReleaseAll { target: previous }];
        if previous != self.local.node {
            actions.push(Action::ReleaseAll {
                target: self.local.node,
            });
        }
        self.active = self.local;
        self.held.clear();
        self.remote_alive_at = None;
        actions.push(Action::TargetChanged {
            target: self.local.node,
        });
        let display = self
            .topology
            .display(self.local)
            .expect("validated local display cannot be removed");
        actions.push(Action::Warp {
            target: self.local.node,
            display: self.local,
            point: Point {
                x: display.origin.x + display.width / 2.0,
                y: display.origin.y + display.height / 2.0,
            },
        });
        actions
    }
    pub fn disconnect(&mut self, peer: NodeId) -> Vec<Action> {
        if self.active.node == peer && peer != self.local.node {
            self.emergency_return()
        } else {
            vec![]
        }
    }
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<Action>, ControlError> {
        self.check_time(now_ms)?;
        if self.expired(now_ms) {
            return Ok(self.emergency_return());
        }
        Ok(vec![])
    }
    pub fn heartbeat(&mut self, peer: NodeId, now_ms: u64) -> Result<(), ControlError> {
        self.check_time(now_ms)?;
        if self.active.node == peer && peer != self.local.node {
            if self.expired(now_ms) {
                return Err(ControlError::Timeout);
            }
            self.remote_alive_at = Some(now_ms);
        }
        Ok(())
    }
    fn expired(&self, now_ms: u64) -> bool {
        self.remote_alive_at
            .is_some_and(|alive| now_ms - alive >= self.timeout_ms)
    }
    pub fn permission_lost(&mut self) -> Vec<Action> {
        self.input_available = false;
        self.emergency_return()
    }
    /// Call only after the adapter observes a real user-session permission grant.
    pub fn permission_restored(&mut self) {
        self.input_available = !self.stopped;
    }
    pub fn shutdown(&mut self) -> Vec<Action> {
        self.stopped = true;
        self.emergency_return()
    }
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ControlError {}
