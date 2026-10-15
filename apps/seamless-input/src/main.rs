use std::{
    fmt,
    io::{self, Write},
    process::ExitCode,
    time::{Duration, SystemTime},
};

use clap::{Args, Parser, Subcommand};
use seamless_discovery::Discovery;
use seamless_input::{
    supervisor::{AppPaths, CapabilityReport, NativeSupervisor},
    tui,
};
use seamless_input_protocol::{NodeId, VERSION};
use seamless_transport::{IdentityStore, PairingCode, PairingSession};

const EXIT_OPERATIONAL_FAILURE: u8 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "seamless-input",
    version,
    about = "Symmetric peer input sharing"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start this machine as a SeamlessInput peer.
    Start,
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
        Commands::Start => start(&paths).await,
        Commands::Pair(args) => pair(&paths, &args.code),
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
    let mut supervisor = NativeSupervisor::bootstrap(paths)?;
    let state = supervisor.tick().await?;
    println!(
        "SeamlessInput running: {} display(s), {} authenticated session(s)",
        state.displays, state.authenticated_sessions
    );
    io::stdout()
        .flush()
        .map_err(|error| OperationalError(error.to_string()))?;
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = interval.tick() => { supervisor.tick().await?; }
            result = tokio::signal::ctrl_c() => {
                result.map_err(|error| OperationalError(error.to_string()))?;
                return Ok(());
            }
        }
    }
}

fn pair(paths: &AppPaths, value: &str) -> Result<(), OperationalError> {
    let identity = IdentityStore::open_or_create(&paths.identity, "SeamlessInput peer")?;
    let mut discovery = Discovery::new(VERSION).map_err(OperationalError)?;
    if value == "new" {
        let mut code = PairingCode::generate(SystemTime::now())?;
        let phrase = code.phrase().to_owned();
        let _session = PairingSession::offer(&identity, &mut code, SystemTime::now())?;
        let nearby = discovery
            .browse(Duration::from_millis(150))
            .map_err(OperationalError)?;
        println!("Pairing code: {phrase}");
        println!(
            "Pairable peers currently discovered: {}",
            nearby
                .iter()
                .filter(|peer| peer.advertisement.pairable)
                .count()
        );
        println!("The code expires in five minutes and is accepted only once.");
        Ok(())
    } else {
        let _session = PairingSession::accept(&identity, value)?;
        let pairable = discovery
            .browse(Duration::from_millis(250))
            .map_err(OperationalError)?
            .into_iter()
            .filter(|peer| peer.compatible && peer.advertisement.pairable)
            .count();
        if pairable == 0 {
            return Err(OperationalError(
                "no compatible pairable peer was discovered; the pairing code was not logged"
                    .into(),
            ));
        }
        println!("Pairing request prepared for {pairable} compatible peer(s).");
        Ok(())
    }
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
    if report {
        println!("SeamlessInput diagnostic report");
        println!("privacy: redacted");
        println!("platform: {}", std::env::consts::OS);
        println!("permissions: measured in current user session");
    } else {
        println!("SeamlessInput doctor");
        println!("administrator elevation: not required");
        println!("user consent: checked separately from administrator elevation");
    }
    println!("config: {}", measured.config);
    println!("input access: {}", measured.input);
    println!("clipboard access: {}", measured.clipboard);
    println!("displays: {}", measured.displays);
    println!("discovery: {}", measured.discovery);
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
