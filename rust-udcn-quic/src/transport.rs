//! High-level NDN transport over QUIC.
//!
//! This module provides a high-level API for NDN communications over QUIC,
//! handling connection establishment, Interest/Data exchange, and event handling.

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, trace, warn};
use rust_udcn_common::{
    ndn::{Data, Interest, Name},
    metrics::UdcnMetrics,
};
use std::{
    net::ToSocketAddrs,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, RwLock},
    time::timeout,
};

use crate::{
    face::{Face, FaceEvent},
    ClientOptions, NdnQuicClient, ServerOptions, NdnQuicServer,
    DEFAULT_INTEREST_TIMEOUT_MS,
};

/// NDN QUIC transport modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// Client mode
    Client,
    /// Server mode
    Server,
    /// Dual mode (both client and server)
    Dual,
}

/// Configuration for the NDN QUIC transport
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Transport mode
    pub mode: TransportMode,
    
    /// Server options (only used in Server or Dual mode)
    pub server_options: Option<ServerOptions>,
    
    /// Client options
    pub client_options: ClientOptions,
    
    /// Event buffer size
    pub event_buffer_size: usize,
    
    /// Interest timeout (in milliseconds)
    pub interest_timeout_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mode: TransportMode::Client,
            server_options: None,
            client_options: ClientOptions::default(),
            event_buffer_size: 100,
            interest_timeout_ms: DEFAULT_INTEREST_TIMEOUT_MS,
        }
    }
}

/// Events emitted by the transport
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A new face was created
    FaceCreated(String),
    
    /// A face was closed
    FaceClosed(String),
    
    /// An Interest was received
    InterestReceived {
        /// The Interest
        interest: Interest,
        
        /// ID of the face it was received on
        face_id: String,
    },
    
    /// A Data packet was received
    DataReceived {
        /// The Data
        data: Data,
        
        /// ID of the face it was received on
        face_id: String,
    },
    
    /// An error occurred
    Error(String),
}

/// High-level NDN transport over QUIC
#[derive(Debug)]
pub struct NdnQuicTransport {
    /// Configuration
    config: TransportConfig,
    
    /// QUIC client (if in Client or Dual mode)
    client: Option<Arc<NdnQuicClient>>,
    
    /// QUIC server (if in Server or Dual mode)
    server: Option<Arc<NdnQuicServer>>,
    
    /// Connected faces
    faces: Arc<RwLock<Vec<Arc<Face>>>>,
    
    /// Event sender
    event_sender: mpsc::Sender<TransportEvent>,
    
    /// Event receiver
    event_receiver: Arc<RwLock<Option<mpsc::Receiver<TransportEvent>>>>,
    
    /// Metrics
    metrics: Arc<UdcnMetrics>,
}

impl NdnQuicTransport {
    /// Create a new transport with the given configuration
    pub async fn new(config: TransportConfig) -> Result<Self> {
        // Create the event channel
        let (event_sender, event_receiver) = mpsc::channel(config.event_buffer_size);
        
        // Create metrics
        let metrics = Arc::new(UdcnMetrics::new());
        
        // Create client and/or server based on the mode
        let client = match config.mode {
            TransportMode::Client | TransportMode::Dual => {
                let client = NdnQuicClient::new(config.client_options.clone()).await?;
                Some(Arc::new(client))
            }
            _ => None,
        };
        
        let server = match config.mode {
            TransportMode::Server | TransportMode::Dual => {
                let server_options = config.server_options.clone()
                    .ok_or_else(|| anyhow!("Server options are required in Server or Dual mode"))?;
                
                let server = NdnQuicServer::new(server_options).await?;
                Some(Arc::new(server))
            }
            _ => None,
        };
        
        let transport = Self {
            config,
            client,
            server,
            faces: Arc::new(RwLock::new(Vec::new())),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            metrics,
        };
        
        // Start the server if we have one
        if let Some(server) = &transport.server {
            server.run().await?;
        }
        
        // Start the event processor
        transport.process_events();
        
        Ok(transport)
    }

    /// Connect to a remote NDN forwarder
    pub async fn connect<T: ToSocketAddrs + std::fmt::Debug>(&self, addr: T) -> Result<Arc<Face>> {
        let client = self.client.clone()
            .ok_or_else(|| anyhow!("Client not initialized (transport is not in Client or Dual mode)"))?;
        
        let face = client.connect(addr).await?;
        
        // Add the face to our list
        self.faces.write().await.push(Arc::clone(&face));
        
        // Emit an event
        let _ = self.event_sender.send(TransportEvent::FaceCreated(face.id().to_string())).await;
        
        Ok(face)
    }

    /// Express an Interest and wait for Data
    pub async fn express_interest(
        &self,
        interest: Interest,
        face_id: Option<&str>,
        timeout_ms: Option<u64>,
    ) -> Result<Data> {
        let faces = self.faces.read().await;
        
        // Find the face to use
        let face = match face_id {
            // Use the specified face if provided
            Some(id) => {
                faces.iter()
                    .find(|f| f.id() == id)
                    .ok_or_else(|| anyhow!("Face not found: {}", id))?
                    .clone()
            }
            // Otherwise use the first available face
            None => {
                if faces.is_empty() {
                    return Err(anyhow!("No faces available"));
                }
                Arc::clone(&faces[0])
            }
        };
        
        // Express the Interest
        face.express_interest(
            interest, 
            timeout_ms.unwrap_or(self.config.interest_timeout_ms)
        ).await
    }

    /// Send a Data packet
    pub async fn send_data(
        &self,
        data: Data,
        face_id: &str,
    ) -> Result<()> {
        let faces = self.faces.read().await;
        
        // Find the face to use
        let face = faces.iter()
            .find(|f| f.id() == face_id)
            .ok_or_else(|| anyhow!("Face not found: {}", face_id))?;
        
        // Send the Data
        face.send_data(data).await
    }

    /// Get the next event from the transport
    pub async fn next_event(&self) -> Option<TransportEvent> {
        let mut receiver_guard = self.event_receiver.write().await;
        let receiver = receiver_guard.as_mut()?;
        receiver.recv().await
    }

    /// Get metrics from the transport
    pub fn metrics(&self) -> Arc<UdcnMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Get a list of all connected faces
    pub async fn get_faces(&self) -> Vec<Arc<Face>> {
        self.faces.read().await.clone()
    }

    /// Close the transport and all connections
    pub async fn close(&self) -> Result<()> {
        // Close all faces
        let faces = self.faces.read().await.clone();
        for face in faces {
            face.close().await;
        }
        
        // Close the client if we have one
        if let Some(client) = &self.client {
            client.close().await?;
        }
        
        // Close the server if we have one
        if let Some(server) = &self.server {
            server.stop().await?;
        }
        
        Ok(())
    }

    /// Process events from all faces
    fn process_events(&self) {
        let faces = Arc::clone(&self.faces);
        let event_sender = self.event_sender.clone();
        
        tokio::spawn(async move {
            loop {
                // Get a snapshot of the current faces
                let current_faces = faces.read().await.clone();
                
                // Wait for events from any face
                for face in &current_faces {
                    if let Some(event) = face.next_event().await {
                        match event {
                            FaceEvent::InterestReceived(interest) => {
                                let _ = event_sender.send(TransportEvent::InterestReceived {
                                    interest,
                                    face_id: face.id().to_string(),
                                }).await;
                            }
                            FaceEvent::DataReceived(data) => {
                                let _ = event_sender.send(TransportEvent::DataReceived {
                                    data,
                                    face_id: face.id().to_string(),
                                }).await;
                            }
                            FaceEvent::Closed => {
                                let _ = event_sender.send(TransportEvent::FaceClosed(
                                    face.id().to_string(),
                                )).await;
                                
                                // Remove the face from our list
                                let mut faces_write = faces.write().await;
                                faces_write.retain(|f| f.id() != face.id());
                            }
                            FaceEvent::Error(error) => {
                                let _ = event_sender.send(TransportEvent::Error(
                                    format!("Face {}: {}", face.id(), error),
                                )).await;
                            }
                        }
                    }
                }
                
                // Sleep a bit to avoid busy-waiting
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }
}
