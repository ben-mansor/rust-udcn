use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::{debug, error, info, trace, warn};
use rust_udcn_common::ndn::{Data, Interest, Name};
use rust_udcn_xdp::XdpManager;
use std::{net::IpAddr, path::PathBuf, time::Duration};
use tokio::time::sleep;

mod commands;
mod utils;

/// µDCN Command Line Interface
#[derive(Parser)]
#[clap(author, version, about)]
struct Cli {
    /// Sets the level of verbosity
    #[clap(short, long, global = true)]
    verbose: bool,

    /// Subcommand to execute
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage the XDP program
    Xdp {
        #[clap(subcommand)]
        cmd: XdpCommands,
    },
    
    /// Manage the forwarding table (FIB)
    Fib {
        #[clap(subcommand)]
        cmd: FibCommands,
    },
    
    /// Send Interest and receive Data packets
    Interest {
        /// Name to request (NDN URI format)
        name: String,
        
        /// Timeout in milliseconds
        #[clap(short, long, default_value = "4000")]
        timeout: u64,
        
        /// Interface to send from
        #[clap(short, long)]
        interface: Option<String>,
    },
    
    /// Publish Data under a name
    Publish {
        /// Name to publish under (NDN URI format)
        name: String,
        
        /// Content to publish (string)
        content: String,
        
        /// Time-to-live in milliseconds
        #[clap(short, long, default_value = "60000")]
        ttl: u32,
        
        /// Interface to publish on
        #[clap(short, long)]
        interface: Option<String>,
    },
    
    /// Benchmark the NDN forwarder
    Benchmark {
        /// Number of Interests to send
        #[clap(short, long, default_value = "1000")]
        count: usize,
        
        /// Name prefix to use for benchmark
        #[clap(short, long, default_value = "/benchmark")]
        prefix: String,
        
        /// Number of concurrent requests
        #[clap(short, long, default_value = "1")]
        concurrent: usize,
    },
}

#[derive(Subcommand)]
enum XdpCommands {
    /// Load the XDP program
    Load {
        /// Path to the XDP object file
        #[clap(short, long)]
        file: Option<PathBuf>,
        
        /// Interface to attach to
        #[clap(short, long)]
        interface: String,
        
        /// Use SKB mode (slower but more compatible)
        #[clap(long)]
        skb_mode: bool,
        
        /// Use hardware offload
        #[clap(long)]
        offload: bool,
    },
    
    /// Unload the XDP program
    Unload {
        /// Interface to detach from
        #[clap(short, long)]
        interface: String,
    },
    
    /// Show statistics about the XDP program
    Stats,
}

#[derive(Subcommand)]
enum FibCommands {
    /// Add a route to the FIB
    Add {
        /// Name prefix (NDN URI format)
        prefix: String,
        
        /// Next-hop face ID
        face: u16,
        
        /// Route cost/metric
        #[clap(short, long, default_value = "10")]
        cost: u8,
    },
    
    /// Remove a route from the FIB
    Remove {
        /// Name prefix (NDN URI format)
        prefix: String,
    },
    
    /// Show all routes in the FIB
    Show,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(
        if cli.verbose { "debug" } else { "info" }
    )).init();
    
    // Execute the specified command
    match cli.command {
        Commands::Xdp { cmd } => {
            commands::xdp::handle_command(cmd).await?;
        },
        Commands::Fib { cmd } => {
            commands::fib::handle_command(cmd).await?;
        },
        Commands::Interest { name, timeout, interface } => {
            commands::interest::send_interest(name, timeout, interface).await?;
        },
        Commands::Publish { name, content, ttl, interface } => {
            commands::publish::publish_data(name, content, ttl, interface).await?;
        },
        Commands::Benchmark { count, prefix, concurrent } => {
            commands::benchmark::run_benchmark(count, prefix, concurrent).await?;
        },
    }
    
    Ok(())
}
