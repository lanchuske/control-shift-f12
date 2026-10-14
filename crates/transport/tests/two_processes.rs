use seamless_discovery::mdns::Discovery;
use seamless_input_protocol::NodeId;
use seamless_transport::quic::*;
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
mod support;

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect()
}

struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_processes_with_manual_fallback() {
    exercise(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_processes_with_real_mdns() {
    exercise(true).await;
}

async fn exercise(discovery_enabled: bool) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().to_vec();
    let key = cert.signing_key.serialize_der();
    let (server, client) = support::configs_from_der(der.clone(), key.clone());
    let parent = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([1; 16]),
        server,
        client,
        EndpointOptions::default(),
    )
    .unwrap();
    let instance = format!(
        "{:032x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut discovery = if discovery_enabled {
        Some(Discovery::new(1).unwrap())
    } else {
        None
    };
    if let Some(discovery) = &mut discovery {
        discovery
            .publish(&instance, parent.local_addr(), false)
            .unwrap();
    }
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "process_peer", "--nocapture"])
        .env("SEAMLESS_TEST_WORKER", "1")
        .env("SEAMLESS_TEST_CERT", encode(&der))
        .env("SEAMLESS_TEST_KEY", encode(&key))
        .env("SEAMLESS_TEST_PARENT", parent.local_addr().to_string())
        .env(
            "SEAMLESS_TEST_DISCOVERY",
            if discovery_enabled { "1" } else { "0" },
        )
        .env("SEAMLESS_TEST_INSTANCE", &instance)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut child = Worker(child);
    let stdout = child.0.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let child_address = loop {
        let line = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("worker did not report an endpoint");
        if let Some(address) = line.strip_prefix("CHILD_ADDR=") {
            break address.parse().unwrap();
        }
    };
    writeln!(child.0.stdin.as_mut().unwrap(), "GO").unwrap();
    let _ = parent
        .dial(child_address, "localhost", Some(NodeId([2; 16])))
        .await;
    loop {
        let sessions = parent.sessions();
        if sessions.len() == 1 && sessions[0].initiator() == NodeId([1; 16]) {
            assert_eq!(sessions[0].trust(), SessionTrust::PendingIdentity);
            assert!(sessions[0].authenticated_connection().is_none());
            break;
        }
        assert!(Instant::now() < deadline, "parent did not elect a session");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    writeln!(child.0.stdin.as_mut().unwrap(), "FINISH").unwrap();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "worker failed");
            break;
        }
        assert!(Instant::now() < deadline, "worker failed to finish");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    reader.join().unwrap();
}

// Invoked only as a separate process by the two parent tests above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "subprocess helper"]
async fn process_peer() {
    if std::env::var("SEAMLESS_TEST_WORKER").is_err() {
        return;
    }
    let (server, client) = support::configs_from_der(
        decode(&std::env::var("SEAMLESS_TEST_CERT").unwrap()),
        decode(&std::env::var("SEAMLESS_TEST_KEY").unwrap()),
    );
    let peer = PeerEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodeId([2; 16]),
        server,
        client,
        EndpointOptions::default(),
    )
    .unwrap();
    println!("CHILD_ADDR={}", peer.local_addr());
    std::io::stdout().flush().unwrap();
    let mut signal = String::new();
    std::io::stdin().read_line(&mut signal).unwrap();
    assert_eq!(signal.trim(), "GO");
    let address = if std::env::var("SEAMLESS_TEST_DISCOVERY").unwrap() == "1" {
        let mut discovery = Discovery::new(1).unwrap();
        let instance = std::env::var("SEAMLESS_TEST_INSTANCE").unwrap();
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            let peers = discovery.browse(Duration::from_millis(100)).unwrap();
            if let Some(peer) = peers
                .iter()
                .find(|peer| peer.advertisement.instance == instance)
            {
                assert!(peer.compatible);
                break peer.advertisement.addresses[0];
            }
            assert!(Instant::now() < deadline, "worker did not discover parent");
        }
    } else {
        seamless_discovery::mdns::manual_address(&std::env::var("SEAMLESS_TEST_PARENT").unwrap())
            .unwrap()[0]
    };
    let _ = peer.dial(address, "localhost", Some(NodeId([1; 16]))).await;
    signal.clear();
    std::io::stdin().read_line(&mut signal).unwrap();
    assert_eq!(signal.trim(), "FINISH");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let sessions = peer.sessions();
        if sessions.len() == 1 && sessions[0].initiator() == NodeId([1; 16]) {
            assert!(!sessions[0].is_closed());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "worker did not elect canonical session"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
