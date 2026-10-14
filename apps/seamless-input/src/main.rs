use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

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
    Doctor,
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

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(EXIT_OPERATIONAL_FAILURE)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Start => println!("Starting SeamlessInput peer"),
        Commands::Pair(args) if args.code == "new" => println!("Creating pairing code"),
        Commands::Pair(args) => println!("Pairing with code: {}", args.code),
        Commands::Peers => println!("Listing peers"),
        Commands::Unpair { peer } => println!("Unpairing peer: {peer}"),
        Commands::Tui => println!("Opening topology interface"),
        Commands::Doctor => println!("Running diagnostics"),
        Commands::Config { command } => match command {
            ConfigCommands::Show => println!("Showing configuration"),
            ConfigCommands::Path => println!("Configuration path"),
        },
    }
    Ok(())
}
