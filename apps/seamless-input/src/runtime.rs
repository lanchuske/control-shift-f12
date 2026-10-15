use crate::peer::{Capabilities, PeerMessage, PeerRegistry};
use seamless_input_core::clipboard::{ClipboardDeduper, ClipboardError, ClipboardPayload};
use seamless_input_core::platform::{ClipboardContent, PlatformClipboard, PlatformInput};
use seamless_input_core::{
    Action, ControlError, Controller, DisplayId, Edge, NodeId, Point, Topology,
};
use seamless_input_protocol::InputEvent;
use seamless_transport::{PinnedPeer, SessionTrust};

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeEffect {
    Local(InputEvent),
    Send { peer: NodeId, message: PeerMessage },
    ReleaseLocal,
    WarpLocal { display: DisplayId, point: Point },
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeReceive {
    None,
    Input(InputEvent),
    Clipboard(ClipboardPayload),
    ReleaseInput,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    SessionNotTrusted,
    Lease(crate::peer::LeaseError),
    Clipboard(ClipboardError),
    Control(ControlError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError<I, C> {
    Input(I),
    Clipboard(C),
}

pub fn apply_receive<I: PlatformInput, C: PlatformClipboard>(
    input: &mut I,
    clipboard: &mut C,
    received: RuntimeReceive,
) -> Result<(), ApplyError<I::Error, C::Error>> {
    match received {
        RuntimeReceive::None => Ok(()),
        RuntimeReceive::ReleaseInput => input.release_all().map_err(ApplyError::Input),
        RuntimeReceive::Input(event) => input.inject(&event).map_err(ApplyError::Input),
        RuntimeReceive::Clipboard(ClipboardPayload::Text(text)) => clipboard
            .write_remote(&ClipboardContent::Text(text))
            .map_err(ApplyError::Clipboard),
        RuntimeReceive::Clipboard(ClipboardPayload::Png(bytes)) => clipboard
            .write_remote(&ClipboardContent::Png(bytes))
            .map_err(ApplyError::Clipboard),
    }
}
impl From<crate::peer::LeaseError> for RuntimeError {
    fn from(v: crate::peer::LeaseError) -> Self {
        Self::Lease(v)
    }
}
impl From<ClipboardError> for RuntimeError {
    fn from(v: ClipboardError) -> Self {
        Self::Clipboard(v)
    }
}
impl From<ControlError> for RuntimeError {
    fn from(v: ControlError) -> Self {
        Self::Control(v)
    }
}

pub struct Runtime {
    local: NodeId,
    controller: Controller,
    peers: PeerRegistry,
    sequence: u64,
    clipboard: ClipboardDeduper,
}
impl Runtime {
    pub fn new(
        local: NodeId,
        display: DisplayId,
        topology: Topology,
        timeout_ms: u64,
    ) -> Result<Self, ControlError> {
        Ok(Self {
            local,
            controller: Controller::new(topology, display, timeout_ms)?,
            peers: PeerRegistry::new(local),
            sequence: 0,
            clipboard: ClipboardDeduper::new(256),
        })
    }
    fn connect(&mut self, peer: NodeId, caps: Capabilities) -> u64 {
        self.peers.connected(peer, caps)
    }
    /// Admit only a mutually authenticated QUIC session whose node is present
    /// in the durable pairing store. Discovery alone never grants admission.
    pub fn connect_admitted(
        &mut self,
        peer: NodeId,
        caps: Capabilities,
        pin: Option<&PinnedPeer>,
        trust: SessionTrust,
    ) -> Result<u64, RuntimeError> {
        if pin.is_none_or(|p| p.node_id != peer) || trust != SessionTrust::Authenticated {
            return Err(RuntimeError::SessionNotTrusted);
        }
        Ok(self.connect(peer, caps))
    }
    pub fn active_peer(&self) -> NodeId {
        self.controller.active_target()
    }
    pub fn peer_epoch(&self, peer: NodeId) -> Option<u64> {
        self.peers.epoch(peer)
    }
    pub fn route(&mut self, event: InputEvent) -> Result<Vec<RuntimeEffect>, ControlError> {
        let actions = self.controller.route(event)?;
        Ok(self.effects(actions))
    }
    pub fn cross(
        &mut self,
        edge: Edge,
        point: Point,
        now_ms: u64,
    ) -> Result<Vec<RuntimeEffect>, ControlError> {
        let actions = self.controller.cross(edge, point, now_ms)?;
        Ok(self.effects(actions))
    }
    pub fn disconnect(&mut self, peer: NodeId) -> Vec<RuntimeEffect> {
        self.peers.disconnected(peer);
        let actions = self.controller.disconnect(peer);
        self.effects(actions)
    }
    /// Atomically replace display routing. Any remote lease is released before
    /// the new topology becomes active so stale placement state cannot retain
    /// control of local input.
    pub fn reconfigure(
        &mut self,
        local_display: DisplayId,
        topology: Topology,
        timeout_ms: u64,
    ) -> Result<Vec<RuntimeEffect>, ControlError> {
        let actions = self.controller.emergency_return();
        let effects = self.effects(actions);
        self.controller = Controller::new(topology, local_display, timeout_ms)?;
        Ok(effects)
    }
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<RuntimeEffect>, ControlError> {
        let actions = self.controller.tick(now_ms)?;
        Ok(self.effects(actions))
    }
    pub fn receive(
        &mut self,
        peer: NodeId,
        message: PeerMessage,
        now_ms: u64,
    ) -> Result<RuntimeReceive, RuntimeError> {
        self.peers.receive(peer, message.clone())?;
        match message {
            PeerMessage::Input { event, .. } => Ok(RuntimeReceive::Input(event)),
            PeerMessage::Clipboard { transfer, .. } => Ok(self
                .clipboard
                .accept_remote(transfer)?
                .map(RuntimeReceive::Clipboard)
                .unwrap_or(RuntimeReceive::None)),
            PeerMessage::Heartbeat { .. } => {
                self.controller.heartbeat(peer, now_ms)?;
                Ok(RuntimeReceive::None)
            }
            PeerMessage::ReleaseLease { .. } => Ok(RuntimeReceive::ReleaseInput),
            PeerMessage::Capabilities { .. } | PeerMessage::AcquireLease { .. } => {
                Ok(RuntimeReceive::None)
            }
        }
    }
    /// Recover local control without waiting for the remote peer. The returned
    /// effects deliberately put remote release first, followed by unconditional
    /// local cleanup and cursor recovery.
    pub fn emergency_return(&mut self) -> Vec<RuntimeEffect> {
        let actions = self.controller.emergency_return();
        self.effects(actions)
    }
    pub fn offer_clipboard(
        &mut self,
        payload: ClipboardPayload,
    ) -> Result<Vec<RuntimeEffect>, RuntimeError> {
        let Some(transfer) = self.clipboard.accept_local(payload)? else {
            return Ok(vec![]);
        };
        let peers: Vec<_> = self.peers.peers().collect();
        let mut out = vec![];
        for (peer, epoch, caps) in peers {
            let allowed = match transfer.payload {
                ClipboardPayload::Text(_) => caps.text,
                ClipboardPayload::Png(_) => caps.png,
            };
            if allowed {
                self.sequence = self.sequence.saturating_add(1);
                out.push(RuntimeEffect::Send {
                    peer,
                    message: PeerMessage::Clipboard {
                        epoch,
                        sequence: self.sequence,
                        transfer: transfer.clone(),
                    },
                })
            }
        }
        Ok(out)
    }
    pub fn heartbeat_effects(&self) -> Vec<RuntimeEffect> {
        self.peers
            .peers()
            .map(|(peer, epoch, _)| RuntimeEffect::Send {
                peer,
                message: PeerMessage::Heartbeat { epoch },
            })
            .collect()
    }
    fn effects(&mut self, actions: Vec<Action>) -> Vec<RuntimeEffect> {
        let mut out = vec![];
        for action in actions {
            match action {
                Action::Local(e) => out.push(RuntimeEffect::Local(e)),
                Action::Send { target, event } => self.send_input(target, event, &mut out),
                Action::ReleaseAll { target } if target == self.local => {
                    out.push(RuntimeEffect::ReleaseLocal)
                }
                Action::ReleaseAll { target } => {
                    if let Some(epoch) = self.peers.epoch(target) {
                        out.push(RuntimeEffect::Send {
                            peer: target,
                            message: PeerMessage::ReleaseLease { epoch },
                        })
                    }
                }
                Action::Warp {
                    target,
                    display,
                    point,
                } if target == self.local => out.push(RuntimeEffect::WarpLocal { display, point }),
                Action::Warp { target, point, .. } => self.send_input(
                    target,
                    InputEvent::Pointer {
                        x: point.x,
                        y: point.y,
                    },
                    &mut out,
                ),
                Action::TargetChanged { target } if target != self.local => {
                    if let Some(epoch) = self.peers.epoch(target) {
                        out.push(RuntimeEffect::Send {
                            peer: target,
                            message: PeerMessage::AcquireLease { epoch },
                        })
                    }
                }
                Action::TargetChanged { .. } => {}
            }
        }
        out
    }
    fn send_input(&mut self, target: NodeId, event: InputEvent, out: &mut Vec<RuntimeEffect>) {
        if let Some(epoch) = self.peers.epoch(target) {
            self.sequence = self.sequence.saturating_add(1);
            out.push(RuntimeEffect::Send {
                peer: target,
                message: PeerMessage::Input {
                    epoch,
                    sequence: self.sequence,
                    event,
                },
            })
        }
    }
}
