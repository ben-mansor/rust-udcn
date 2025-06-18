//! Interest sending command implementation for µDCN CLI

use anyhow::{Context, Result};
use log::{debug, info, warn};
use rust_udcn_common::{ndn::{Interest, Name}, types::FaceId};
use rust_udcn_quic::{ClientOptions, NdnQuicClient, NdnQuicTransport, TransportConfig, TransportMode};
use tokio::time::timeout;

/// Send an Interest and print the Data response
pub async fn send_interest(name_str: String, timeout_ms: u64, interface: Option<String>) -> Result<()> {
    info!("Sending Interest: name={}, timeout={}ms", name_str, timeout_ms);
    
    // Parse the name string into a Name
    let name = Name::from_string(&name_str)?;
    
    // Create an Interest packet
    let mut interest = Interest::new(name);
    interest.set_can_be_prefix(false);
    interest.set_must_be_fresh(true);
    
    println!("Sending Interest: {}", name_str);
    println!("Timeout: {}ms", timeout_ms);
    
    // Determine how to send the Interest:
    // 1. If an interface is specified, use XDP to send via that interface
    // 2. Otherwise, use QUIC transport to send via default route
    if let Some(iface) = interface {
        send_via_xdp(interest, &iface, timeout_ms).await?;
    } else {
        send_via_quic(interest, timeout_ms).await?;
    }
    
    Ok(())
}

/// Send an Interest via the XDP forwarder
async fn send_via_xdp(interest: Interest, interface: &str, timeout_ms: u64) -> Result<()> {
    info!("Sending Interest via XDP on interface {}", interface);
    
    // In a real implementation, we'd interact with the XDP forwarder
    // to send the Interest via a specific interface
    
    println!("Note: Sending via specific interface is not fully implemented.");
    println!("In a real implementation, this would send the Interest via the XDP forwarder");
    println!("on interface {} with timeout {}ms.", interface, timeout_ms);
    
    // For demonstration, show what we're trying to do
    println!("\nInterest details:");
    println!("  Name: {}", interest.name());
    println!("  CanBePrefix: {}", interest.can_be_prefix());
    println!("  MustBeFresh: {}", interest.must_be_fresh());
    
    Ok(())
}

/// Send an Interest via QUIC transport
async fn send_via_quic(interest: Interest, timeout_ms: u64) -> Result<()> {
    info!("Sending Interest via QUIC");
    
    // Configure the QUIC transport
    let config = TransportConfig {
        mode: TransportMode::Client,
        client_options: ClientOptions {
            verify_certificate: false, // For testing only
            ..Default::default()
        },
        interest_timeout_ms: timeout_ms,
        ..Default::default()
    };
    
    // Create the transport
    let transport = NdnQuicTransport::new(config).await
        .context("Failed to create QUIC transport")?;
    
    // Connect to a default NDN router (localhost in this case)
    println!("Connecting to localhost:6367...");
    let face = transport.connect(("localhost", 6367)).await
        .context("Failed to connect to NDN router")?;
    
    println!("Connected. Sending Interest...");
    
    // Send the Interest and wait for Data
    match timeout(
        std::time::Duration::from_millis(timeout_ms),
        transport.express_interest(interest.clone(), Some(face.id()), None)
    ).await {
        Ok(Ok(data)) => {
            println!("\nReceived Data:");
            println!("  Name: {}", data.name());
            println!("  Content-Type: {}", data.content_type());
            println!("  Freshness Period: {} ms", data.freshness_period_ms());
            
            // Print content (truncate if too long)
            let content = data.content();
            if content.len() <= 100 {
                println!("  Content: {:?}", content);
                
                // If content looks like UTF-8 text, print it as string
                if let Ok(text) = String::from_utf8(content.to_vec()) {
                    println!("  Content (as text): {}", text);
                }
            } else {
                println!("  Content: {} bytes", content.len());
                println!("  Content (first 100 bytes): {:?}", &content[..100]);
            }
        }
        Ok(Err(e)) => {
            println!("Error retrieving data: {}", e);
        }
        Err(_) => {
            println!("Timeout after {}ms", timeout_ms);
        }
    }
    
    // Close the transport
    transport.close().await?;
    
    Ok(())
}
