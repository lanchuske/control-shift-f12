//! Setup-only process. Deliberately owns no NativeSupervisor, input adapter,
//! clipboard adapter, identity writer, discovery, or network listener.
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
