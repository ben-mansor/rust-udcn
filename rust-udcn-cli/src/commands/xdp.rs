//! XDP command implementation for µDCN CLI

use anyhow::{Context, Result};
use log::{debug, info, warn};
use std::path::PathBuf;
use rust_udcn_xdp::XdpManager;

use crate::XdpCommands;

/// Handle XDP-related commands
pub async fn handle_command(cmd: XdpCommands) -> Result<()> {
    match cmd {
        XdpCommands::Load { file, interface, skb_mode, offload } => {
            load_xdp(file, interface, skb_mode, offload).await
        }
        XdpCommands::Unload { interface } => {
            unload_xdp(interface).await
        }
        XdpCommands::Stats => {
            show_xdp_stats().await
        }
    }
}

/// Load and attach the XDP program
async fn load_xdp(
    file: Option<PathBuf>,
    interface: String,
    skb_mode: bool,
    offload: bool,
) -> Result<()> {
    info!("Loading XDP program...");
    
    // Create XDP manager
    let mut xdp = match file {
        Some(path) => {
            info!("Loading XDP program from file: {}", path.display());
            XdpManager::load_from_file(path).await?
        }
        None => {
            info!("Loading embedded XDP program");
            XdpManager::load_from_embedded().await?
        }
    };
    
    // Attach to the specified interface
    info!("Attaching to interface: {}", interface);
    xdp.attach(&interface)?;
    
    info!("XDP program loaded and attached to {}", interface);
    
    // Print status information
    println!("XDP program loaded and attached to interface: {}", interface);
    
    // Show initial metrics
    let metrics = xdp.get_metrics().await;
    println!("\nInitial metrics:");
    println!("  Packets processed: {}", metrics.packets_total.count());
    println!("  Interests received: {}", metrics.interests_received.count());
    println!("  Data packets received: {}", metrics.data_received.count());
    
    Ok(())
}

/// Unload and detach the XDP program
async fn unload_xdp(interface: String) -> Result<()> {
    info!("Unloading XDP program from interface: {}", interface);
    
    // Create XDP manager and detach
    // Since we don't have persistent state, we need to reload the program first
    let mut xdp = XdpManager::load_from_embedded().await?;
    
    // Attach and then detach to ensure proper cleanup
    if let Err(e) = xdp.attach(&interface) {
        warn!("Failed to attach to interface before detaching: {}", e);
        // Continue anyway, as we still want to try to detach
    }
    
    xdp.detach_all()?;
    
    info!("XDP program detached from interface: {}", interface);
    println!("XDP program detached from interface: {}", interface);
    
    Ok(())
}

/// Show XDP statistics
async fn show_xdp_stats() -> Result<()> {
    info!("Fetching XDP statistics");
    
    // We don't have persistent state across CLI invocations
    // In a real implementation, we would have a daemon or persistent state
    // For now, print a message
    println!("XDP statistics are only available for running programs.");
    println!("To see statistics, use this command after loading the XDP program,");
    println!("preferably in another terminal while the program is still running.");
    
    // Dummy implementation: try to load the program to get current metrics
    println!("\nAttempting to get metrics from currently running XDP program...");
    
    match XdpManager::load_from_embedded().await {
        Ok(xdp) => {
            if xdp.is_attached() {
                let metrics = xdp.get_metrics().await;
                
                println!("\nCurrent metrics:");
                println!("Packets:");
                println!("  Total processed: {}", metrics.packets_total.count());
                println!("  Interests received: {}", metrics.interests_received.count());
                println!("  Data received: {}", metrics.data_received.count());
                println!("  Dropped: {}", metrics.packets_dropped.count());
                
                println!("\nContent Store:");
                println!("  Hits: {}", metrics.cs_hits.count());
                println!("  Misses: {}", metrics.cs_misses.count());
                println!("  Hit ratio: {:.2}%", 
                    if metrics.cs_hits.count() + metrics.cs_misses.count() > 0 {
                        (metrics.cs_hits.count() as f64 / 
                         (metrics.cs_hits.count() + metrics.cs_misses.count()) as f64) * 100.0
                    } else {
                        0.0
                    });
                
                println!("\nPIT:");
                println!("  Insertions: {}", metrics.pit_inserts.count());
                println!("  Matches: {}", metrics.pit_matches.count());
                println!("  Expirations: {}", metrics.pit_expirations.count());
                
                println!("\nFIB:");
                println!("  Lookups: {}", metrics.fib_lookups.count());
                println!("  Hits: {}", metrics.fib_hits.count());
                println!("  Hit ratio: {:.2}%", 
                    if metrics.fib_lookups.count() > 0 {
                        (metrics.fib_hits.count() as f64 / metrics.fib_lookups.count() as f64) * 100.0
                    } else {
                        0.0
                    });
                
                println!("\nInterfaces: {:?}", xdp.attached_interfaces());
            } else {
                println!("No XDP program is currently attached.");
            }
        }
        Err(e) => {
            println!("Could not get metrics: {}", e);
        }
    }
    
    Ok(())
}
