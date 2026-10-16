//! Setup-only process. Deliberately owns no NativeSupervisor, input adapter,
//! clipboard adapter, identity writer or network listener. Experimental pairing
//! may browse LAN locators only after a typed, explicit local consent command.
use crate::control_api::{Request, read_request, write_message};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
};

const MAX_REQUESTS: usize = 256;

pub struct ControlEngine {
    engine_id: String,
    requests: BTreeMap<String, (Request, Value)>,
    inventory_generation: u64,
    inventory: Value,
    event_sequence: u64,
    events: Vec<Value>,
    stopped: bool,
    #[cfg(feature = "pairing-v2-experimental")]
    guided: crate::guided_setup::SetupController<crate::guided_setup::OsSetupClock>,
}

impl Default for ControlEngine {
    fn default() -> Self {
        use rand::RngCore;
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        Self {
            engine_id: id.iter().map(|b| format!("{b:02x}")).collect(),
            requests: BTreeMap::new(),
            stopped: false,
            inventory_generation: 0,
            inventory: json!({"status":"not_measured","layout_ready":false}),
            event_sequence: 0,
            events: Vec::new(),
            #[cfg(feature = "pairing-v2-experimental")]
            guided: Default::default(),
        }
    }
}

impl ControlEngine {
    pub fn snapshot(&self) -> Value {
        json!({"engine":self.engine_id,"schema_version":1,
            "build_version":env!("CARGO_PKG_VERSION"),"phase":"foundations",
            "input_enabled":false,"clipboard_enabled":false,
            "pairing_enabled":false,"authenticated_sessions":0,
            "identity":"not_measured","permissions":"not_measured",
            "policy":"not_measured","layout":"not_configured","inventory":self.inventory,
            "last_event_seq":self.event_sequence})
    }

    pub fn handle(&mut self, request: Request) -> Value {
        if let Some((previous, response)) = self.requests.get(&request.id) {
            return if previous == &request {
                response.clone()
            } else {
                error(&request.id, "request_id_conflict")
            };
        }
        if self.requests.len() >= MAX_REQUESTS {
            return error(&request.id, "request_limit");
        }
        let response = if request.v != 1 {
            error(&request.id, "unsupported_version")
        } else if self.stopped {
            error(&request.id, "engine_stopped")
        } else {
            match request.command.as_str() {
                "snapshot" | "diagnostics.snapshot"
                    if request.args.as_object().is_some_and(|a| a.is_empty()) =>
                {
                    json!({"v":1,"id":request.id,"ok":true,"result":self.snapshot()})
                }
                "shutdown" if request.args.as_object().is_some_and(|a| a.is_empty()) => {
                    self.stopped = true;
                    #[cfg(feature = "pairing-v2-experimental")]
                    self.guided.shutdown();
                    self.emit(
                        "EngineStopping",
                        json!({"input_enabled":false,"clipboard_enabled":false}),
                    );
                    json!({"v":1,"id":request.id,"ok":true,"result":{"stopped":true}})
                }
                "inventory.refresh" if request.args.as_object().is_some_and(|a| a.is_empty()) => {
                    self.inventory_generation += 1;
                    self.inventory = match crate::display_inventory::measure(
                        self.inventory_generation,
                    ) {
                        Ok(inventory) => {
                            json!({"status":"measured_logical_only","layout_ready":false,"data":inventory})
                        }
                        Err(reason) => {
                            json!({"status":"unavailable","layout_ready":false,"reason":reason})
                        }
                    };
                    self.emit("InventoryChanged", self.inventory.clone());
                    json!({"v":1,"id":request.id,"ok":true,"result":self.snapshot()})
                }
                "snapshot" | "diagnostics.snapshot" | "shutdown" | "inventory.refresh" => {
                    error(&request.id, "invalid_arguments")
                }
                #[cfg(feature = "pairing-v2-experimental")]
                "pairing.v2" => self.guided_request(&request),
                _ => error(&request.id, "not_available_in_foundations"),
            }
        };
        self.requests
            .insert(request.id.clone(), (request, response.clone()));
        response
    }

    fn emit(&mut self, event: &str, data: Value) {
        // At most one event per accepted request; the request bound prevents overflow.
        self.event_sequence += 1;
        self.events.push(json!({"v":1,"engine":self.engine_id,"seq":self.event_sequence,"event":event,"data":data}));
    }

    #[cfg(feature = "pairing-v2-experimental")]
    fn guided_request(&mut self, request: &Request) -> Value {
        use crate::guided_setup::{SetupCommand, SetupError};
        let command: SetupCommand = match serde_json::from_value(request.args.clone()) {
            Ok(command) => command,
            Err(_) => return error(&request.id, "invalid_arguments"),
        };
        let changes = !matches!(
            command,
            SetupCommand::Snapshot {} | SetupCommand::CompareMatch {}
        );
        match self.guided.execute(command) {
            Ok(snapshot) => {
                let value = serde_json::to_value(snapshot).expect("typed snapshot serialization");
                if changes {
                    self.emit("PairingV2Changed", value.clone());
                }
                json!({"v":1,"id":request.id,"ok":true,"result":value})
            }
            Err(reason) => {
                if matches!(
                    reason,
                    SetupError::OperationalContractPending
                        | SetupError::Expired
                        | SetupError::Unavailable
                ) && let Ok(snapshot) = self.guided.execute(SetupCommand::Snapshot {})
                {
                    self.emit(
                        "PairingV2Changed",
                        serde_json::to_value(snapshot).expect("typed snapshot serialization"),
                    );
                }
                let code = serde_json::to_value(reason).expect("typed error serialization");
                error(&request.id, code.as_str().expect("enum is a string"))
            }
        }
    }
}

fn error(id: &str, code: &str) -> Value {
    json!({"v":1,"id":id,"ok":false,"error":{"code":code,"retryable":false}})
}

pub fn run_stdio(mut reader: impl Read, mut writer: impl Write) -> io::Result<()> {
    let mut engine = ControlEngine::default();
    while let Some(request) = read_request(&mut reader)? {
        write_message(&mut writer, &engine.handle(request))?;
        for event in engine.events.drain(..) {
            write_message(&mut writer, &event)?;
        }
        if engine.stopped {
            break;
        }
    }
    // There is no capture or lease to release: this process cannot acquire one.
    Ok(())
}
