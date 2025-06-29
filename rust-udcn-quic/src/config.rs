//! Configuration for QUIC transport.
//!
//! This module provides configuration options for QUIC servers and clients.

use anyhow::{Context, Result};
use quinn::{ClientConfig, ServerConfig, VarInt};
use rustls::{Certificate, PrivateKey};
use std::{
    fs::File,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use crate::NDN_QUIC_ALPN;

/// Server configuration options
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// Address to listen on
    pub listen_addr: String,
    
    /// Path to the certificate file
    pub cert_path: PathBuf,
    
    /// Path to the private key file
    pub key_path: PathBuf,
    
    /// Maximum idle timeout (in milliseconds)
    pub idle_timeout_ms: Option<u64>,
    
    /// Keep alive interval (in milliseconds)
    pub keep_alive_interval_ms: Option<u64>,
    
    /// Maximum connections
    pub max_connections: Option<u32>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:6367".to_string(),
            cert_path: PathBuf::from("cert.pem"),
            key_path: PathBuf::from("key.pem"),
            idle_timeout_ms: Some(30000),
            keep_alive_interval_ms: Some(5000),
            max_connections: Some(1000),
        }
    }
}

/// Client configuration options
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Path to the CA certificate file (optional)
    pub ca_cert_path: Option<PathBuf>,
    
    /// Maximum idle timeout (in milliseconds)
    pub idle_timeout_ms: Option<u64>,
    
    /// Keep alive interval (in milliseconds)
    pub keep_alive_interval_ms: Option<u64>,
    
    /// Whether to verify the server certificate
    pub verify_certificate: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            ca_cert_path: None,
            idle_timeout_ms: Some(30000),
            keep_alive_interval_ms: Some(5000),
            verify_certificate: true,
        }
    }
}

/// Configure a QUIC server
pub async fn configure_server(options: &ServerOptions) -> Result<ServerConfig> {
    // Read certificate and private key
    let cert = read_certificate(&options.cert_path)?;
    let key = read_private_key(&options.key_path)?;
    
    // Create server configuration
    let mut server_config = ServerConfig::with_single_cert(vec![cert], key)
        .context("Failed to create server config with certificate")?;
    
    // Configure the transport parameters
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .context("Failed to get mutable transport config")?;
    
    // Set idle timeout
    if let Some(idle_timeout_ms) = options.idle_timeout_ms {
        transport_config.max_idle_timeout(Some(VarInt::from_u32(idle_timeout_ms as u32)));
    }
    
    // Set keep alive interval
    if let Some(keep_alive_ms) = options.keep_alive_interval_ms {
        transport_config.keep_alive_interval(Some(Duration::from_millis(keep_alive_ms)));
    }
    
    // Configure the server
    let server_config_mut = Arc::get_mut(&mut server_config.transport)
        .context("Failed to get mutable server config")?;
    
    // Set ALPN protocols
    server_config.alpn_protocols = vec![NDN_QUIC_ALPN.to_vec()];
    
    // Set maximum connections
    if let Some(max_connections) = options.max_connections {
        server_config_mut.max_concurrent_uni_streams(VarInt::from_u32(max_connections));
    }
    
    Ok(server_config)
}

/// Configure a QUIC client
pub async fn configure_client(options: &ClientOptions) -> Result<ClientConfig> {
    // Create client crypto configuration
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_native_roots()
        .with_no_client_auth();
    
    // Add custom CA certificate if specified
    if let Some(ca_path) = &options.ca_cert_path {
        let ca_cert = read_certificate(ca_path)?;
        let mut cert_store = rustls::RootCertStore::empty();
        cert_store.add(&ca_cert)?;
        
        client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(cert_store)
            .with_no_client_auth();
    }
    
    // If verification is disabled (not recommended), skip verification
    if !options.verify_certificate {
        let mut dangerous_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification {}))
            .with_no_client_auth();
        
        dangerous_config.enable_early_data = true;
        dangerous_config.alpn_protocols = vec![NDN_QUIC_ALPN.to_vec()];
        
        return Ok(ClientConfig::new(Arc::new(dangerous_config)));
    }
    
    // Enable early data and set ALPN protocols
    client_crypto.enable_early_data = true;
    client_crypto.alpn_protocols = vec![NDN_QUIC_ALPN.to_vec()];
    
    // Create QUIC client configuration
    let mut client_config = ClientConfig::new(Arc::new(client_crypto));
    
    // Configure the transport parameters
    let transport_config = Arc::get_mut(&mut client_config.transport)
        .context("Failed to get mutable transport config")?;
    
    // Set idle timeout
    if let Some(idle_timeout_ms) = options.idle_timeout_ms {
        transport_config.max_idle_timeout(Some(VarInt::from_u32(idle_timeout_ms as u32)));
    }
    
    // Set keep alive interval
    if let Some(keep_alive_ms) = options.keep_alive_interval_ms {
        transport_config.keep_alive_interval(Some(Duration::from_millis(keep_alive_ms)));
    }
    
    Ok(client_config)
}

/// Read a certificate from a file
fn read_certificate<P: AsRef<Path>>(path: P) -> Result<Certificate> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("Failed to open certificate file: {}", path.as_ref().display()))?;
    let mut reader = BufReader::new(file);
    
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| anyhow::anyhow!("Failed to parse certificate"))?;
    
    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificate found"));
    }
    
    Ok(Certificate(certs[0].clone()))
}

/// Read a private key from a file
fn read_private_key<P: AsRef<Path>>(path: P) -> Result<PrivateKey> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("Failed to open key file: {}", path.as_ref().display()))?;
    let mut reader = BufReader::new(file);
    
    // Try PKCS8 format first
    if let Ok(keys) = rustls_pemfile::pkcs8_private_keys(&mut reader) {
        if !keys.is_empty() {
            return Ok(PrivateKey(keys[0].clone()));
        }
    }
    
    // Rewind the reader
    reader.seek(std::io::SeekFrom::Start(0))?;
    
    // Try RSA format
    if let Ok(keys) = rustls_pemfile::rsa_private_keys(&mut reader) {
        if !keys.is_empty() {
            return Ok(PrivateKey(keys[0].clone()));
        }
    }
    
    Err(anyhow::anyhow!("No private key found"))
}

/// A certificate verifier that accepts any server certificate
struct SkipServerVerification;

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
