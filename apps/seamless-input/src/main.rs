use std::{fmt, process::ExitCode};

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

#[derive(Debug)]
enum OperationalError {
    NotImplemented(&'static str),
}

impl fmt::Display for OperationalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented(command) => {
                write!(formatter, "{command} is not implemented yet")
            }
        }
    }
}

fn run(cli: Cli) -> Result<(), OperationalError> {
    let command = match cli.command {
        Commands::Start => "start",
        Commands::Pair(_args) => "pair",
        Commands::Peers => "peers",
        Commands::Unpair { peer: _ } => "unpair",
        Commands::Tui => "tui",
        Commands::Doctor => "doctor",
        Commands::Config { command } => match command {
            ConfigCommands::Show => "config show",
            ConfigCommands::Path => "config path",
        },
    };
    Err(OperationalError::NotImplemented(command))
}
