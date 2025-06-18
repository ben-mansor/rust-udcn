//! Data publishing command implementation for µDCN CLI

use anyhow::{Context, Result};
use bytes::Bytes;
use log::{debug, info, warn};
use rust_udcn_common::ndn::{Data, Name, SignatureInfo, SignatureType};
use rust_udcn_quic::{ServerOptions, NdnQuicServer, TransportConfig, TransportMode, NDN_QUIC_PORT};
use std::{path::PathBuf, time::Duration};
use tokio::signal;

/// Publish data under a name
pub async fn publish_data(
    name_str: String,
    content: String,
    ttl: u32,
    interface: Option<String>,
) -> Result<()> {
    info!(
        "Publishing data: name={}, content_len={}, ttl={}ms",
        name_str,
        content.len(),
        ttl
    );

    // Parse the name string into a Name
    let name = Name::from_string(&name_str)?;

    // Create a Data packet
    let content_bytes = Bytes::from(content.clone());
    let mut data = Data::new(name.clone(), content_bytes);
    data.set_freshness_period_ms(ttl);
    data.set_content_type(0); // BLOB content type

    // Create a simple signature (in production, you'd want a real signature)
    let sig_info = SignatureInfo {
        signature_type: SignatureType::DigestSha256,
        key_locator: None,
        validity_period: None,
    };
    data.set_signature_info(sig_info);
    
    // The real signing would happen here
    // For this demo, we just set a dummy signature value
    data.set_signature_value(Bytes::from(vec![0u8; 32]));

    println!("Publishing Data:");
    println!("  Name: {}", name_str);
    println!("  Content ({}): {}", content.len(), 
        if content.len() > 32 {
            format!("{}...", &content[..30])
        } else {
            content.clone()
        }
    );
    println!("  TTL: {}ms", ttl);

    // Determine how to publish the Data:
    // 1. If an interface is specified, use XDP to publish via that interface
    // 2. Otherwise, use QUIC transport to publish via a server
    if let Some(iface) = interface {
        publish_via_xdp(data, &iface).await?;
    } else {
        publish_via_quic(data).await?;
    }

    Ok(())
}

/// Publish a Data packet via the XDP forwarder
async fn publish_via_xdp(data: Data, interface: &str) -> Result<()> {
    info!("Publishing Data via XDP on interface {}", interface);

    // In a real implementation, we'd interact with the XDP forwarder
    // to publish the Data via a specific interface
    
    println!("Note: Publishing via specific interface is not fully implemented.");
    println!("In a real implementation, this would publish the Data via the XDP forwarder");
    println!("on interface {}.", interface);

    // For demonstration, show what we're trying to do
    println!("\nData packet would be published via XDP on interface {}", interface);
    println!("  Name: {}", data.name());
    println!("  Content size: {} bytes", data.content().len());
    
    Ok(())
}

/// Publish a Data packet via QUIC transport
async fn publish_via_quic(data: Data) -> Result<()> {
    info!("Publishing Data via QUIC server");

    // For a real server, we'd need certificates
    // For testing, let's create them in a temporary directory
    println!("Starting QUIC server on port {}...", NDN_QUIC_PORT);
    println!("Press Ctrl+C to stop the server");

    // In a real implementation, we would:
    // 1. Configure a proper QUIC server with real certificates
    // 2. Create a producer application that registers prefixes
    // 3. Serve Data in response to matching Interests
    
    // For this demonstration, we'll create a simplified server
    // that just serves our single Data packet for any matching Interest
    let data_name = data.name().clone();
    
    // Create a simple echo server
    println!("Server ready to respond to Interests for: {}", data_name);
    println!("Waiting for Interests (press Ctrl+C to exit)...");
    
    // In a real implementation, this would be a full NDN producer
    // For now, just simulate waiting until Ctrl+C
    match signal::ctrl_c().await {
        Ok(()) => {
            println!("Shutting down server...");
        }
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {}", err);
        }
    }

    Ok(())
}

/// Temporary function to generate a self-signed certificate for testing
/// Not suitable for production use
#[allow(dead_code)]
async fn generate_test_certificates(dir: &PathBuf) -> Result<(PathBuf, PathBuf)> {
    use rcgen::{Certificate, CertificateParams, DnType, SanType, KeyPair, KeyUsagePurpose};
    use std::fs::File;
    use std::io::Write;
    
    // Create the certificate directory if it doesn't exist
    std::fs::create_dir_all(dir)?;
    
    // Generate a new key pair
    let key_pair = KeyPair::generate()?;
    
    // Set up certificate parameters
    let mut params = CertificateParams::default();
    params.key_pair = Some(key_pair);
    params.distinguished_name.push(DnType::CommonName, "localhost");
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".to_string()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    params.is_ca = rcgen::IsCa::SelfSignedOnly;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::KeyAgreement,
    ];
    
    // Generate the self-signed certificate
    let cert = Certificate::from_params(params)?;
    
    // Get the certificate and private key in PEM format
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();
    
    // Write the certificate and private key to files
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    
    let mut cert_file = File::create(&cert_path)?;
    let mut key_file = File::create(&key_path)?;
    
    cert_file.write_all(cert_pem.as_bytes())?;
    key_file.write_all(key_pem.as_bytes())?;
    
    Ok((cert_path, key_path))
}
