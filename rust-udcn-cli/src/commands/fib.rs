//! FIB command implementation for µDCN CLI

use anyhow::{Context, Result};
use log::{debug, info, warn};
use rust_udcn_common::ndn::Name;
use rust_udcn_xdp::XdpManager;

use crate::FibCommands;

/// Handle FIB-related commands
pub async fn handle_command(cmd: FibCommands) -> Result<()> {
    match cmd {
        FibCommands::Add { prefix, face, cost } => {
            add_route(prefix, face, cost).await
        }
        FibCommands::Remove { prefix } => {
            remove_route(prefix).await
        }
        FibCommands::Show => {
            show_routes().await
        }
    }
}

/// Add a route to the FIB
async fn add_route(prefix_str: String, face: u16, cost: u8) -> Result<()> {
    info!("Adding route: prefix={}, face={}, cost={}", prefix_str, face, cost);
    
    // Parse the prefix string into a Name
    let prefix = Name::from_string(&prefix_str)?;
    
    // Load the XDP manager
    let xdp = XdpManager::load_from_embedded().await?;
    
    // Add the route
    xdp.add_route(&prefix, face.into(), cost).await?;
    
    info!("Route added successfully");
    println!("Added route: {} -> face {} (cost {})", prefix_str, face, cost);
    
    Ok(())
}

/// Remove a route from the FIB
async fn remove_route(prefix_str: String) -> Result<()> {
    info!("Removing route: prefix={}", prefix_str);
    
    // Parse the prefix string into a Name
    let prefix = Name::from_string(&prefix_str)?;
    
    // Load the XDP manager
    let xdp = XdpManager::load_from_embedded().await?;
    
    // Remove the route
    xdp.remove_route(&prefix).await?;
    
    info!("Route removed successfully");
    println!("Removed route: {}", prefix_str);
    
    Ok(())
}

/// Show all routes in the FIB
async fn show_routes() -> Result<()> {
    info!("Showing all routes in FIB");
    
    // Load the XDP manager
    let xdp = XdpManager::load_from_embedded().await?;
    
    // In a real implementation, we would implement a method to list all FIB entries
    // For now, display a message about the limitation
    println!("FIB route listing is not fully implemented in this version.");
    println!("This would show all routes in the FIB along with their face IDs and costs.");
    
    // Get the FIB component
    let fib = xdp.fib();
    
    // Here we would iterate through the FIB entries and display them
    println!("\nFIB management functions available:");
    println!("  - Add route:    rust-udcn-cli fib add <prefix> <face> --cost <cost>");
    println!("  - Remove route: rust-udcn-cli fib remove <prefix>");
    
    Ok(())
}
