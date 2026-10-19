#![cfg(feature = "pairing-v2-g4")]

use seamless_input::g4_pairing::{G4Command, G4Event, G4PairingWorker, G4WorkerBackend};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Default)]
struct Probe {
    commands: Vec<G4Command>,
    stopped: bool,
}

struct Backend(Arc<Mutex<Probe>>);

impl G4WorkerBackend for Backend {
    fn command(&mut self, command: G4Command) -> Vec<G4Event> {
        std::thread::sleep(Duration::from_millis(100));
        self.0.lock().unwrap().commands.push(command);
        Vec::new()
    }

    fn poll(&mut self) -> Vec<G4Event> {
        Vec::new()
    }

    fn shutdown(&mut self) {
        self.0.lock().unwrap().stopped = true;
    }
}

#[test]
fn g4_stdio_worker_backpressure_eof_and_cancel_join_boundedly() {
    let probe = Arc::new(Mutex::new(Probe::default()));
    let mut worker = G4PairingWorker::spawn(Backend(probe.clone())).unwrap();
    let mut rejected = false;
    for generation in 1..=18 {
        if worker.try_command(G4Command::Start { generation }).is_err() {
            rejected = true;
            break;
        }
    }
    assert!(
        rejected,
        "capacity-16 command queue did not apply backpressure"
    );
    worker.shutdown(Duration::from_secs(1)).unwrap();
    assert!(probe.lock().unwrap().stopped);
}

struct BurstBackend;

impl G4WorkerBackend for BurstBackend {
    fn command(&mut self, _command: G4Command) -> Vec<G4Event> {
        (1..=17)
            .map(|generation| G4Event::Browsing { generation })
            .collect()
    }

    fn poll(&mut self) -> Vec<G4Event> {
        Vec::new()
    }
    fn shutdown(&mut self) {}
}

#[test]
fn g4_worker_backpressures_without_dropping_single_use_events() {
    let mut worker = G4PairingWorker::spawn(BurstBackend).unwrap();
    worker
        .try_command(G4Command::Start { generation: 1 })
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    let mut generations = Vec::new();
    while generations.len() < 17 && std::time::Instant::now() < deadline {
        if let Some(G4Event::Browsing { generation }) = worker.try_event() {
            generations.push(generation);
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(generations, (1..=17).collect::<Vec<_>>());
    worker.shutdown(Duration::from_secs(1)).unwrap();
}
