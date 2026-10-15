use seamless_transport::{
    IdentityStore, PairingCode, PairingError, pair_accept_over_quic, pair_offer_over_quic,
};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    time::SystemTime,
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
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
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
async fn two_process_pairing_happy_path() {
    exercise(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_process_pairing_wrong_code_path() {
    exercise(true).await;
}

async fn exercise(wrong: bool) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().to_vec();
    let key = cert.signing_key.serialize_der();
    let mut child = Worker(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "pairing_process_worker",
                "--nocapture",
            ])
            .env("SEAMLESS_PAIR_WORKER", "1")
            .env("SEAMLESS_PAIR_CERT", encode(&der))
            .env("SEAMLESS_PAIR_KEY", encode(&key))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let address = loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if let Some(value) = line.trim().strip_prefix("PAIR_ADDR=") {
            break value.parse().unwrap();
        }
    };
    let dir = tempfile::TempDir::new().unwrap();
    let mut alice = IdentityStore::open_or_create(dir.path(), "Alice").unwrap();
    let now = SystemTime::now();
    let mut code = PairingCode::generate(now).unwrap();
    let sent = if wrong {
        "abandon ability able about above absent"
    } else {
        code.phrase()
    };
    writeln!(child.0.stdin.as_mut().unwrap(), "{sent}").unwrap();
    let (_, client) = support::configs_from_der(der, key);
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client);
    let connection = endpoint
        .connect(address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let result = pair_offer_over_quic(&connection, &mut alice, &mut code, now).await;
    if wrong {
        assert!(
            matches!(result, Err(PairingError::ConfirmationMismatch)),
            "unexpected offer-side result: {result:?}"
        );
    } else {
        assert_eq!(result.unwrap().friendly_name, "Bob");
    }
    let expected = if wrong { "EXPECTED_FAIL" } else { "PASS" };
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if line.trim() == expected {
            break;
        }
    }
    writeln!(child.0.stdin.as_mut().unwrap(), "DONE").unwrap();
    assert!(child.0.wait().unwrap().success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "subprocess helper"]
async fn pairing_process_worker() {
    if std::env::var("SEAMLESS_PAIR_WORKER").is_err() {
        return;
    }
    let (server, _) = support::configs_from_der(
        decode(&std::env::var("SEAMLESS_PAIR_CERT").unwrap()),
        decode(&std::env::var("SEAMLESS_PAIR_KEY").unwrap()),
    );
    let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
    println!("PAIR_ADDR={}", endpoint.local_addr().unwrap());
    std::io::stdout().flush().unwrap();
    let mut phrase = String::new();
    std::io::stdin().read_line(&mut phrase).unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let mut bob = IdentityStore::open_or_create(dir.path(), "Bob").unwrap();
    let connection = endpoint.accept().await.unwrap().await.unwrap();
    let result = pair_accept_over_quic(&connection, &mut bob, phrase.trim()).await;
    match result {
        Ok(peer) => {
            assert_eq!(peer.friendly_name, "Alice");
            println!("PASS");
        }
        Err(PairingError::ConfirmationMismatch) => println!("EXPECTED_FAIL"),
        Err(error) => panic!("unexpected pairing error: {error}"),
    }
    std::io::stdout().flush().unwrap();
    let mut done = String::new();
    std::io::stdin().read_line(&mut done).unwrap();
    assert_eq!(done.trim(), "DONE");
}
