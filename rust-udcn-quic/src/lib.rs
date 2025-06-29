//! QUIC-based NDN transport for μDCN (micro Data-Centric Networking)
//! 
//! This crate provides a QUIC transport layer for NDN, implementing
//! RFC8999, RFC9000, RFC9001, and RFC9002 with NDN packet encapsulation.
//! It enables the transport of NDN packets over QUIC, with support for
//! fragmentation, reassembly, and congestion control.

use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use log::{debug, error, info, trace, warn};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use rustls::{Certificate, PrivateKey};
use rust_udcn_common::{
    ndn::{Data, Interest, Name},
    metrics::UdcnMetrics,
};
use std::{
    collections::HashMap,
    fmt::Debug,
    io::Cursor,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs,
    io::AsyncReadExt,
    sync::{mpsc, Mutex, RwLock},
    time::timeout,
};

mod config;
mod face;
mod fragmentation;
mod packet;
mod transport;

pub use config::{ClientOptions, ServerOptions};
pub use face::{Face, FaceEvent};
pub use transport::NdnQuicTransport;

/// Default QUIC port for NDN
pub const NDN_QUIC_PORT: u16 = 6367;

/// Default ALPN protocol string for NDN over QUIC
pub const NDN_QUIC_ALPN: &[u8] = b"ndn1";

/// Maximum datagram size for NDN over QUIC
pub const MAX_DATAGRAM_SIZE: usize = 1200;

/// Maximum NDN packet size
pub const MAX_PACKET_SIZE: usize = 8800; // RFC 8609 specifies 8800 bytes max

/// Timeout for Interest packets in milliseconds
pub const DEFAULT_INTEREST_TIMEOUT_MS: u64 = 4000;

/// Fragment size for large packets
pub const DEFAULT_FRAGMENT_SIZE: usize = 1000;

/// Server configuration for NDN over QUIC
#[derive(Debug, Clone)]
pub struct NdnQuicServer {
    /// The QUIC endpoint
    endpoint: Endpoint,
    
    /// Server configuration
    server_config: ServerConfig,
    
    /// Address the server is listening on
    address: SocketAddr,
    
    /// Connected faces
    faces: Arc<RwLock<HashMap<String, Arc<Face>>>>,
    
    /// Server metrics
    metrics: Arc<UdcnMetrics>,
}

impl NdnQuicServer {
    /// Create a new QUIC server with the given options
    pub async fn new(options: ServerOptions) -> Result<Self> {
        let server_config = config::configure_server(&options).await?;
        
        // Create a QUIC endpoint
        let endpoint = Endpoint::server(
            server_config.clone(),
            options.listen_addr.parse().context("Invalid listen address")?,
        )?;
        
        let address = endpoint.local_addr()?;
        
        info!("NDN QUIC server listening on {}", address);
        
        Ok(Self {
            endpoint,
            server_config,
            address,
            faces: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(UdcnMetrics::new()),
        })
    }

    /// Start accepting incoming connections
    pub async fn run(&self) -> Result<()> {
        let endpoint = self.endpoint.clone();
        let faces = Arc::clone(&self.faces);
        let metrics = Arc::clone(&self.metrics);
        
        tokio::spawn(async move {
            info!("QUIC server accepting connections");
            
            while let Some(conn) = endpoint.accept().await {
                debug!("Incoming connection from {:?}", conn.remote_address());
                
                let metrics_clone = Arc::clone(&metrics);
                let faces_clone = Arc::clone(&faces);
                
                tokio::spawn(async move {
                    match conn.await {
                        Ok(connection) => {
                            let remote_addr = connection.remote_address();
                            
                            info!("Connection established from {}", remote_addr);
                            
                            // Create a face for this connection
                            let face_id = format!("quic:{}", remote_addr);
                            let face = Face::new_from_connection(face_id.clone(), connection, metrics_clone);
                            
                            // Add the face to our map
                            faces_clone.write().await.insert(face_id.clone(), Arc::new(face));
                            
                            // Process the connection
                            // In a real implementation, we'd handle the connection lifecycle here
                        }
                        Err(e) => {
                            warn!("Connection failed: {}", e);
                        }
                    }
                });
            }
            
            info!("QUIC server stopped accepting connections");
        });
        
        Ok(())
    }

    /// Get a list of connected faces
    pub async fn get_faces(&self) -> Vec<Arc<Face>> {
        let faces = self.faces.read().await;
        faces.values().cloned().collect()
    }

    /// Get the metrics for this server
    pub fn metrics(&self) -> Arc<UdcnMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Get the server address
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    
    /// Stop the server
    pub async fn stop(&self) -> Result<()> {
        // Close all faces
        let faces = self.faces.read().await;
        for (_, face) in faces.iter() {
            face.close().await;
        }
        
        // Close the endpoint
        self.endpoint.close(0u32.into(), b"Server shutting down");
        
        Ok(())
    }
}

/// Client configuration for NDN over QUIC
#[derive(Debug, Clone)]
pub struct NdnQuicClient {
    /// The QUIC endpoint
    endpoint: Endpoint,
    
    /// Client configuration
    client_config: ClientConfig,
    
    /// Connected faces
    faces: Arc<RwLock<HashMap<String, Arc<Face>>>>,
    
    /// Client metrics
    metrics: Arc<UdcnMetrics>,
}

impl NdnQuicClient {
    /// Create a new QUIC client with the given options
    pub async fn new(options: ClientOptions) -> Result<Self> {
        // Configure the client
        let client_config = config::configure_client(&options).await?;
        
        // Create a QUIC endpoint bound to ANY address
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config.clone());
        
        Ok(Self {
            endpoint,
            client_config,
            faces: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(UdcnMetrics::new()),
        })
    }

    /// Connect to a remote NDN forwarder
    pub async fn connect<T: ToSocketAddrs + Debug>(&self, addr: T) -> Result<Arc<Face>> {
        // Resolve the address
        let addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("Failed to resolve address"))?;
        
        debug!("Connecting to {}", addr);
        
        // Connect to the remote endpoint
        let connection = self.endpoint
            .connect(addr, "localhost")?
            .await
            .map_err(|e| anyhow!("Failed to connect: {}", e))?;
        
        info!("Connected to {}", addr);
        
        // Create a face for this connection
        let face_id = format!("quic:{}", addr);
        let face = Face::new_from_connection(face_id.clone(), connection, Arc::clone(&self.metrics));
        
        let face_arc = Arc::new(face);
        
        // Add the face to our map
        self.faces.write().await.insert(face_id, Arc::clone(&face_arc));
        
        Ok(face_arc)
    }

    /// Send an Interest and wait for Data
    pub async fn express_interest(
        &self,
        face: &Face,
        interest: Interest,
        timeout_ms: Option<u64>,
    ) -> Result<Data> {
        face.express_interest(interest, timeout_ms.unwrap_or(DEFAULT_INTEREST_TIMEOUT_MS)).await
    }

    /// Get a list of connected faces
    pub async fn get_faces(&self) -> Vec<Arc<Face>> {
        let faces = self.faces.read().await;
        faces.values().cloned().collect()
    }

    /// Get the metrics for this client
    pub fn metrics(&self) -> Arc<UdcnMetrics> {
        Arc::clone(&self.metrics)
    }
    
    /// Disconnect from all remote endpoints and close the client
    pub async fn close(&self) -> Result<()> {
        // Close all faces
        let faces = self.faces.read().await;
        for (_, face) in faces.iter() {
            face.close().await;
        }
        
        // Close the endpoint
        self.endpoint.close(0u32.into(), b"Client shutting down");
        
        Ok(())
    }
}
