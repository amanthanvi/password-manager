use anyhow::Result;
use clap::{Parser, Subcommand};
use npw_core::VaultId;
use npw_domain::DomainContext;
use npw_storage::initialize_storage;

#[derive(Debug, Parser)]
#[command(name = "npw")]
#[command(about = "Local-first password manager", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Health,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Health) {
        Command::Health => {
            let context = DomainContext::new(VaultId::random());
            let storage_message = initialize_storage(&context);
            println!("{} | {}", npw_core::bootstrap_banner(), storage_message);
        }
    }

    Ok(())
}
