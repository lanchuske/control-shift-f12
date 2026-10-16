use std::{
    fmt,
    io::{self, Write},
    process::ExitCode,
    time::{Duration, Instant, SystemTime},
};

use clap::{Args, Parser, Subcommand};
use seamless_discovery::{Discovery, manual_address};
use seamless_input::{
    diagnostics::compatibility_lines,
    runtime_status::{RuntimeStatus, RuntimeStatusStore},
    supervisor::{AppPaths, CapabilityReport, INPUT_SERVICE_INTERVAL, NativeSupervisor},
    tui,
};
use seamless_input_protocol::{NodeId, VERSION};
use seamless_transport::{IdentityStore, PairingCode, PairingSession};
use seamless_transport::{pair_accept_over_quic, pair_offer_over_quic};

const EXIT_OPERATIONAL_FAILURE: u8 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "seamless-input",
    version,
    about = "Control Shift F12 — symmetric peer input sharing"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Internal setup foundations; input, clipboard and pairing remain disabled.
    Control {
        #[arg(long, required = true)]
        stdio: bool,
    },
    /// Start this machine as a Control Shift F12 peer.
    Start,
    /// Report the currently running peer and authenticated session count.
    Status(StatusArgs),
    /// Pair this machine with another peer.
    Pair(PairArgs),
    /// List paired and discovered peers.
    Peers,
    /// Remove a paired peer.
    Unpair { peer: String },
    /// Open the topology interface.
    Tui,
    /// Check this machine's setup.
    Doctor {
        /// Print a copyable privacy-redacted diagnostic report.
        #[arg(long)]
        report: bool,
    },
    /// Show or locate configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
}

#[derive(Debug, Args)]
struct PairArgs {
    /// Pair using `new` or a six-word pairing code.
    #[arg(value_name = "CODE")]
    code: String,
    /// Connect directly when mDNS discovery is unavailable.
    #[arg(long, value_name = "HOST:PORT")]
    address: Option<String>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// Read only the heartbeat owned by this process id.
    #[arg(long, value_name = "PID")]
    pid: u32,
    /// Print a stable tab-separated record for native launchers.
    #[arg(long)]
    machine: bool,
}

#[derive(Debug, Subcommand)]
enum ConfigCommands {
    /// Display the current configuration.
    Show,
    /// Print the configuration file location.
    Path,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(EXIT_OPERATIONAL_FAILURE)
        }
    }
}

#[derive(Debug)]
struct OperationalError(String);

impl fmt::Display for OperationalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<E: std::error::Error> From<E> for OperationalError {
    fn from(value: E) -> Self {
        Self(value.to_string())
    }
}

async fn run(cli: Cli) -> Result<(), OperationalError> {
    let paths = AppPaths::discover()?;
    match cli.command {
        Commands::Control { stdio: _ } => {
            let _instance =
                seamless_transport::setup_lock::SetupInstanceLock::acquire(&paths.root)?;
            seamless_input::control_engine::run_stdio(io::stdin().lock(), io::stdout().lock())?;
            Ok(())
        }
        Commands::Start => start(&paths).await,
        Commands::Status(args) => status(&paths, args),
        Commands::Pair(args) => pair(&paths, &args.code, args.address.as_deref()).await,
        Commands::Peers => peers(&paths),
        Commands::Unpair { peer } => unpair(&paths, &peer),
        Commands::Tui => Ok(tui::run_terminal(&paths.config_store()?)?),
        Commands::Doctor { report } => {
            doctor(&paths, report);
            Ok(())
        }
        Commands::Config { command } => config(&paths, command),
    }
}

async fn start(paths: &AppPaths) -> Result<(), OperationalError> {
    let process_id = std::process::id();
    let status_store = RuntimeStatusStore::within(&paths.root, process_id);
    if let Err(error) = status_store.clear_owned(process_id) {
        eprintln!("runtime status cleanup unavailable: {error}");
    }
    let _status_lease = RuntimeStatusLease {
        store: status_store.clone(),
        owner_pid: process_id,
    };
    let mut supervisor = NativeSupervisor::bootstrap(paths)?;
    let mut state = supervisor.tick().await?;
    let mut heartbeat_failed = match publish_status(&status_store, process_id, &state) {
        Ok(()) => false,
        Err(error) => {
            eprintln!("runtime status heartbeat unavailable: {error}");
            true
        }
    };
    println!(
        "Control Shift F12 running: {} display(s), {} authenticated session(s)",
        state.displays, state.authenticated_sessions
    );
    io::stdout()
        .flush()
        .map_err(|error| OperationalError(error.to_string()))?;
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut input_interval = tokio::time::interval(INPUT_SERVICE_INTERVAL);
    input_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_heartbeat = Instant::now();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let next = supervisor.tick().await?;
                let changed = next.displays != state.displays
                    || next.authenticated_sessions != state.authenticated_sessions;
                if changed || last_heartbeat.elapsed() >= Duration::from_secs(2) {
                    match publish_status(&status_store, process_id, &next) {
                        Ok(()) if heartbeat_failed => {
                            eprintln!("runtime status heartbeat recovered");
                            heartbeat_failed = false;
                        }
                        Ok(()) => heartbeat_failed = false,
                        Err(error) if !heartbeat_failed => {
                            eprintln!("runtime status heartbeat unavailable: {error}");
                            heartbeat_failed = true;
                        }
                        Err(_) => {}
                    }
                    last_heartbeat = Instant::now();
                }
                state = next;
            }
            _ = input_interval.tick() => { supervisor.service_input().await?; }
            result = tokio::signal::ctrl_c() => {
                result.map_err(|error| OperationalError(error.to_string()))?;
                return Ok(());
            }
        }
    }
}

fn publish_status(
    store: &RuntimeStatusStore,
    process_id: u32,
    state: &seamless_input::supervisor::SupervisorStatus,
) -> Result<(), seamless_input::runtime_status::RuntimeStatusError> {
    RuntimeStatus::live(process_id, state.displays, state.authenticated_sessions)
        .and_then(|status| store.publish(&status))
}

struct RuntimeStatusLease {
    store: RuntimeStatusStore,
    owner_pid: u32,
}

impl Drop for RuntimeStatusLease {
    fn drop(&mut self) {
        let _ = self.store.clear_owned(self.owner_pid);
    }
}

fn status(paths: &AppPaths, args: StatusArgs) -> Result<(), OperationalError> {
    let store = RuntimeStatusStore::within(&paths.root, args.pid);
    if let Some(status) = store.read_current(SystemTime::now())? {
        if args.machine {
            println!(
                "state=running\tprocess_id={}\tdisplays={}\tauthenticated_sessions={}",
                status.process_id, status.displays, status.authenticated_sessions
            );
        } else {
            println!("{}", status.display_line());
        }
    } else {
        if args.machine {
            println!(
                "state=stopped\tprocess_id={}\tdisplays=0\tauthenticated_sessions=0",
                args.pid
            );
        } else {
            println!("Control Shift F12 stopped: 0 authenticated session(s)");
        }
    }
    Ok(())
}

async fn pair(
    paths: &AppPaths,
    value: &str,
    manual_peer: Option<&str>,
) -> Result<(), OperationalError> {
    let mut identity = IdentityStore::open_or_create(&paths.identity, "SeamlessInput peer")?;
    let mut discovery = Discovery::new(VERSION).map_err(OperationalError)?;
    if value == "new" {
        if manual_peer.is_some() {
            return Err(OperationalError(
                "--address is used with a six-word code, not with `pair new`".into(),
            ));
        }
        let mut code = PairingCode::generate(SystemTime::now())?;
        let phrase = code.phrase().to_owned();
        let server = identity.temporary_pairing_server_config()?;
        let endpoint =
            quinn::Endpoint::server(server, std::net::SocketAddr::new(local_lan_ip(), 0)).map_err(
                |_| OperationalError("temporary pairing listener could not start".into()),
            )?;
        let instance = random_instance();
        discovery
            .publish(
                &instance,
                endpoint.local_addr().map_err(|_| {
                    OperationalError("temporary pairing listener has no address".into())
                })?,
                true,
            )
            .map_err(OperationalError)?;
        let pairing_address = endpoint
            .local_addr()
            .map_err(|_| OperationalError("temporary pairing listener has no address".into()))?;
        println!("Pairing code: {phrase}");
        println!("Pairing address: {pairing_address}");
        println!("The code expires in five minutes and is accepted only once.");
        io::stdout()
            .flush()
            .map_err(|error| OperationalError(error.to_string()))?;
        let incoming = tokio::time::timeout(Duration::from_secs(300), endpoint.accept())
            .await
            .map_err(|_| OperationalError("pairing code expired before a peer connected".into()))?
            .ok_or_else(|| OperationalError("temporary pairing listener stopped".into()))?;
        let connection = tokio::time::timeout(Duration::from_secs(10), incoming)
            .await
            .map_err(|_| OperationalError("pairing connection timed out".into()))?
            .map_err(|_| OperationalError("pairing connection failed".into()))?;
        let peer =
            match pair_offer_over_quic(&connection, &mut identity, &mut code, SystemTime::now())
                .await
            {
                Ok(peer) => peer,
                Err(error) => {
                    // A failed confirmation is still a protocol response the
                    // dialing side must receive. Briefly retain the endpoint so
                    // encrypted error-path frames survive process teardown.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    connection.close(1u32.into(), b"pairing rejected");
                    return Err(error.into());
                }
            };
        // The dialing CLI closes only after it has received and persisted our
        // confirmation. Waiting for that close prevents this short-lived
        // listener from tearing down the final QUIC packet too early.
        if tokio::time::timeout(Duration::from_secs(2), connection.closed())
            .await
            .is_err()
        {
            connection.close(0u32.into(), b"pairing complete");
        }
        println!("Paired with {}.", peer.friendly_name);
        Ok(())
    } else {
        // Validate before touching the network. The session is intentionally
        // discarded; the real PAKE session is created after QUIC connects.
        let _validation = PairingSession::accept(&identity, value)?;
        let address = if let Some(value) = manual_peer {
            *manual_address(value)
                .map_err(OperationalError)?
                .first()
                .ok_or_else(|| OperationalError("manual peer address did not resolve".into()))?
        } else {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut pairable = Vec::new();
            while tokio::time::Instant::now() < deadline && pairable.is_empty() {
                pairable = discovery
                    .browse(Duration::from_millis(200))
                    .map_err(OperationalError)?
                    .into_iter()
                    .filter(|peer| peer.compatible && peer.advertisement.pairable)
                    .collect();
            }
            if pairable.is_empty() {
                return Err(OperationalError(
                    "no compatible pairable peer was discovered; use --address HOST:PORT for manual fallback"
                        .into(),
                ));
            }
            if pairable.len() != 1 {
                return Err(OperationalError(
                    "multiple pairable peers were discovered; wait until only the intended peer is pairable"
                        .into(),
                ));
            }
            *pairable[0].advertisement.addresses.first().ok_or_else(|| {
                OperationalError("pairable peer advertised no usable address".into())
            })?
        };
        let bind = if address.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let mut endpoint = quinn::Endpoint::client(bind)
            .map_err(|_| OperationalError("temporary pairing client could not start".into()))?;
        endpoint.set_default_client_config(IdentityStore::temporary_pairing_client_config()?);
        let connection = tokio::time::timeout(
            Duration::from_secs(10),
            endpoint
                .connect(address, "seamless-input.local")
                .map_err(|_| OperationalError("pairing connection could not start".into()))?,
        )
        .await
        .map_err(|_| OperationalError("pairing connection timed out".into()))?
        .map_err(|_| OperationalError("pairing connection failed".into()))?;
        let peer = pair_accept_over_quic(&connection, &mut identity, value).await?;
        connection.close(0u32.into(), b"pairing complete");
        let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
        println!("Paired with {}.", peer.friendly_name);
        Ok(())
    }
}

fn local_lan_ip() -> std::net::IpAddr {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("192.0.2.1:9")?;
            socket.local_addr().map(|address| address.ip())
        })
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

fn random_instance() -> String {
    use rand::RngCore;
    let mut token = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut token);
    token.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn peers(paths: &AppPaths) -> Result<(), OperationalError> {
    let identity = IdentityStore::open_or_create(&paths.identity, "SeamlessInput peer")?;
    let paired: Vec<_> = identity.peers().collect();
    println!("Paired peers: {}", paired.len());
    for peer in paired {
        println!("- {} ({})", peer.friendly_name, node_hex(peer.node_id));
    }
    let mut discovery = Discovery::new(VERSION).map_err(OperationalError)?;
    let nearby = discovery
        .browse(Duration::from_millis(150))
        .map_err(OperationalError)?;
    println!("Nearby peers: {}", nearby.len());
    Ok(())
}

fn unpair(paths: &AppPaths, selector: &str) -> Result<(), OperationalError> {
    let mut identity = IdentityStore::open_or_create(&paths.identity, "SeamlessInput peer")?;
    let peer_id = identity
        .peers()
        .find(|peer| peer.friendly_name == selector || node_hex(peer.node_id) == selector)
        .map(|peer| peer.node_id)
        .ok_or_else(|| OperationalError("paired peer was not found".into()))?;
    if !identity.unpair(peer_id)? {
        return Err(OperationalError("paired peer was not found".into()));
    }
    println!("Peer removed.");
    Ok(())
}

fn config(paths: &AppPaths, command: ConfigCommands) -> Result<(), OperationalError> {
    let store = paths.config_store()?;
    match command {
        ConfigCommands::Show => {
            let config = store.load_or_default()?;
            print!(
                "{}",
                toml::to_string_pretty(&config)
                    .map_err(|error| OperationalError(error.to_string()))?
            );
        }
        ConfigCommands::Path => println!("{}", store.path().display()),
    }
    Ok(())
}

fn doctor(paths: &AppPaths, report: bool) {
    let measured = CapabilityReport::measure(paths);
    let diagnostics = measured.diagnostics();
    if report {
        println!("Control Shift F12 diagnostic report");
        println!("privacy: redacted");
        println!("platform: {}", std::env::consts::OS);
        println!("permissions: measured in current user session");
    } else {
        println!("Control Shift F12 doctor");
        println!("administrator elevation: not required");
        println!("user consent: checked separately from administrator elevation");
    }
    for (label, value) in compatibility_lines(&diagnostics.rows) {
        println!("{label}: {value}");
    }
    println!("config: {}", measured.config);
    println!("UDP transport: {}", measured.udp_transport);
    println!("paired identity pins: {}", measured.identity);
    println!("enterprise restrictions: not bypassed");
    if !report {
        println!("Use --report to generate a copyable redacted report.");
    }
}

fn node_hex(node: NodeId) -> String {
    node.0.iter().map(|byte| format!("{byte:02x}")).collect()
}
