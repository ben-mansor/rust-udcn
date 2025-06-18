//! NDN face implementation over QUIC transport.
//!
//! This module provides an implementation of NDN faces that operate over QUIC connections.

use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use log::{debug, error, info, trace, warn};
use quinn::{Connection, RecvStream, SendStream};
use rust_udcn_common::{
    ndn::{Data, Interest, InterestResult, Name},
    metrics::UdcnMetrics,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, oneshot, Mutex, RwLock},
    time::timeout,
};

use crate::{
    fragmentation::{assemble_fragments, fragment_packet},
    packet::NdnPacket,
    DEFAULT_FRAGMENT_SIZE, DEFAULT_INTEREST_TIMEOUT_MS,
};

/// Events emitted by a Face
#[derive(Debug, Clone)]
pub enum FaceEvent {
    /// A new Interest was received
    InterestReceived(Interest),
    
    /// A new Data packet was received
    DataReceived(Data),
    
    /// The face was closed
    Closed,
    
    /// An error occurred on the face
    Error(String),
}

/// An NDN face over QUIC transport
#[derive(Debug)]
pub struct Face {
    /// Unique identifier for this face
    id: String,
    
    /// QUIC connection
    connection: Connection,
    
    /// Whether the face is closed
    closed: Arc<Mutex<bool>>,
    
    /// Pending Interests waiting for Data
    pending_interests: Arc<Mutex<HashMap<String, oneshot::Sender<InterestResult>>>>,
    
    /// Receiver for face events
    event_receiver: Arc<Mutex<Option<mpsc::Receiver<FaceEvent>>>>,
    
    /// Sender for face events
    event_sender: Arc<Mutex<mpsc::Sender<FaceEvent>>>,
    
    /// Metrics for this face
    metrics: Arc<UdcnMetrics>,
}

impl Face {
    /// Create a new face from a QUIC connection
    pub fn new_from_connection(
        id: String,
        connection: Connection,
        metrics: Arc<UdcnMetrics>,
    ) -> Self {
        let (event_sender, event_receiver) = mpsc::channel(100);
        
        let face = Self {
            id,
            connection,
            closed: Arc::new(Mutex::new(false)),
            pending_interests: Arc::new(Mutex::new(HashMap::new())),
            event_receiver: Arc::new(Mutex::new(Some(event_receiver))),
            event_sender: Arc::new(Mutex::new(event_sender)),
            metrics,
        };
        
        // Start processing incoming streams
        face.process_incoming_streams();
        
        face
    }

    /// Get the face ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Send an Interest and wait for Data
    pub async fn express_interest(
        &self,
        interest: Interest,
        timeout_ms: u64,
    ) -> Result<Data> {
        // Check if the face is closed
        if *self.closed.lock().await {
            return Err(anyhow!("Face is closed"));
        }
        
        let name = interest.name().to_string();
        
        debug!("[Face {}] Express Interest: {}", self.id, name);
        
        // Create a channel for receiving the Data
        let (sender, receiver) = oneshot::channel();
        
        // Store the sender in our pending interests
        self.pending_interests.lock().await.insert(name.clone(), sender);
        
        // Start a timer to track processing time
        let start = Instant::now();
        
        // Send the Interest packet
        self.send_packet(NdnPacket::Interest(interest.clone())).await?;
        
        // Increment the counter
        self.metrics.interests_sent.increment();
        
        // Wait for the Data with a timeout
        let result = match timeout(Duration::from_millis(timeout_ms), receiver).await {
            Ok(result) => match result {
                Ok(InterestResult::Data(data)) => {
                    // Measure the RTT
                    let rtt = start.elapsed().as_micros() as u64;
                    debug!("[Face {}] Received Data for {}, RTT: {}µs", self.id, name, rtt);
                    
                    // Record the RTT in the metrics
                    self.metrics.interest_processing_time.histogram().observe(rtt);
                    
                    // Increment the counter
                    self.metrics.interests_satisfied.increment();
                    
                    Ok(data)
                }
                Ok(InterestResult::Timeout) => {
                    debug!("[Face {}] Interest timed out: {}", self.id, name);
                    
                    // Increment the counter
                    self.metrics.interests_timed_out.increment();
                    
                    Err(anyhow!("Interest timed out"))
                }
                Ok(InterestResult::NetworkError(err)) => {
                    debug!("[Face {}] Network error for Interest {}: {}", self.id, name, err);
                    Err(anyhow!("Network error: {}", err))
                }
                Err(_) => {
                    debug!("[Face {}] Channel closed for Interest {}", self.id, name);
                    Err(anyhow!("Channel closed"))
                }
            },
            Err(_) => {
                debug!("[Face {}] Interest timed out: {}", self.id, name);
                
                // Remove from pending interests
                self.pending_interests.lock().await.remove(&name);
                
                // Increment the counter
                self.metrics.interests_timed_out.increment();
                
                Err(anyhow!("Interest timed out"))
            }
        };
        
        // Clean up the pending interest if still there
        if !result.is_ok() {
            self.pending_interests.lock().await.remove(&name);
        }
        
        result
    }

    /// Send a Data packet
    pub async fn send_data(&self, data: Data) -> Result<()> {
        debug!("[Face {}] Send Data: {}", self.id, data.name());
        
        // Send the Data packet
        self.send_packet(NdnPacket::Data(data)).await?;
        
        // Increment the counter
        self.metrics.data_sent.increment();
        
        Ok(())
    }

    /// Get the next event from this face
    pub async fn next_event(&self) -> Option<FaceEvent> {
        let mut receiver_guard = self.event_receiver.lock().await;
        let receiver = receiver_guard.as_mut()?;
        receiver.recv().await
    }

    /// Close the face
    pub async fn close(&self) {
        // Set the closed flag
        let mut closed = self.closed.lock().await;
        if *closed {
            return;
        }
        *closed = true;
        
        debug!("[Face {}] Closing", self.id);
        
        // Close all streams
        self.connection.close(0u32.into(), b"Face closed");
        
        // Notify all pending interests
        let mut pending = self.pending_interests.lock().await;
        for (name, sender) in pending.drain() {
            let _ = sender.send(InterestResult::NetworkError("Face closed".to_string()));
        }
        
        // Send a closed event
        if let Ok(sender) = self.event_sender.lock().await.send(FaceEvent::Closed).await {
            debug!("[Face {}] Sent close event", self.id);
        }
    }

    /// Check if the face is closed
    pub async fn is_closed(&self) -> bool {
        *self.closed.lock().await
    }

    /// Process incoming streams from the QUIC connection
    fn process_incoming_streams(&self) {
        let connection = self.connection.clone();
        let closed = Arc::clone(&self.closed);
        let pending_interests = Arc::clone(&self.pending_interests);
        let event_sender = Arc::clone(&self.event_sender);
        let metrics = Arc::clone(&self.metrics);
        let id = self.id.clone();
        
        tokio::spawn(async move {
            debug!("[Face {}] Starting to process incoming streams", id);
            
            // Process incoming bi-directional streams
            while let Ok(Some((send, recv))) = connection.accept_bi().await {
                // Check if we're closed
                if *closed.lock().await {
                    break;
                }
                
                let stream_id = send.id();
                debug!("[Face {}] Accepted bi-directional stream {}", id, stream_id);
                
                // Process this stream
                let stream_closed = Arc::clone(&closed);
                let stream_pending_interests = Arc::clone(&pending_interests);
                let stream_event_sender = Arc::clone(&event_sender);
                let stream_metrics = Arc::clone(&metrics);
                let stream_id_clone = id.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = process_stream(
                        stream_id_clone,
                        stream_id,
                        send,
                        recv,
                        stream_pending_interests,
                        stream_event_sender,
                        stream_metrics,
                    ).await {
                        warn!("[Face {}] Error processing stream {}: {}", id, stream_id, e);
                    }
                });
            }
            
            debug!("[Face {}] Stopped processing incoming streams", id);
            
            // Set the closed flag if not already set
            let mut closed_guard = closed.lock().await;
            if !*closed_guard {
                *closed_guard = true;
                
                // Notify all pending interests
                let mut pending = pending_interests.lock().await;
                for (name, sender) in pending.drain() {
                    let _ = sender.send(InterestResult::NetworkError("Connection closed".to_string()));
                }
                
                // Send a closed event
                if let Ok(sender) = event_sender.lock().await.send(FaceEvent::Closed).await {
                    debug!("[Face {}] Sent close event", id);
                }
            }
        });
    }

    /// Send a packet over the face
    async fn send_packet(&self, packet: NdnPacket) -> Result<()> {
        // Check if the face is closed
        if *self.closed.lock().await {
            return Err(anyhow!("Face is closed"));
        }
        
        // Serialize the packet to bytes
        let bytes = packet.to_bytes()?;
        
        // Update metrics
        self.metrics.bytes_sent.add(bytes.len() as u64);
        
        // Open a new bi-directional stream
        let (mut send, _recv) = self.connection.open_bi().await?;
        
        // Check if we need fragmentation
        if bytes.len() > DEFAULT_FRAGMENT_SIZE {
            debug!(
                "[Face {}] Fragmenting packet of size {} into chunks of {}",
                self.id,
                bytes.len(),
                DEFAULT_FRAGMENT_SIZE
            );
            
            // Fragment the packet
            let fragments = fragment_packet(&bytes, DEFAULT_FRAGMENT_SIZE);
            
            // Send each fragment
            for fragment in fragments {
                send.write_all(&fragment).await?;
            }
        } else {
            // Send the packet directly
            send.write_all(&bytes).await?;
        }
        
        // Finish the stream
        send.finish().await?;
        
        Ok(())
    }
}

/// Process a QUIC stream
async fn process_stream(
    face_id: String,
    stream_id: u64,
    mut send: SendStream,
    mut recv: RecvStream,
    pending_interests: Arc<Mutex<HashMap<String, oneshot::Sender<InterestResult>>>>,
    event_sender: Arc<Mutex<mpsc::Sender<FaceEvent>>>,
    metrics: Arc<UdcnMetrics>,
) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(8192);
    let mut fragments = VecDeque::new();
    
    // Read from the stream
    while let Some(chunk) = recv.read_chunk(1024, false).await? {
        // Update metrics
        metrics.bytes_received.add(chunk.len() as u64);
        
        // Add to our fragments
        fragments.push_back(chunk.bytes);
    }
    
    // Try to assemble the fragments
    let packet_bytes = assemble_fragments(fragments)?;
    
    // Parse as an NDN packet
    let packet = NdnPacket::from_bytes(&packet_bytes)?;
    
    match packet {
        NdnPacket::Interest(interest) => {
            debug!(
                "[Face {}] Received Interest on stream {}: {}",
                face_id,
                stream_id,
                interest.name()
            );
            
            // Update metrics
            metrics.interests_received.increment();
            
            // Send an event
            let event = FaceEvent::InterestReceived(interest);
            event_sender.lock().await.send(event).await?;
        }
        NdnPacket::Data(data) => {
            let name = data.name().to_string();
            debug!(
                "[Face {}] Received Data on stream {}: {}",
                face_id,
                stream_id,
                name
            );
            
            // Update metrics
            metrics.data_received.increment();
            
            // Check if we have a pending interest for this data
            let mut pending = pending_interests.lock().await;
            if let Some(sender) = pending.remove(&name) {
                // Send the data to the waiting Interest
                if sender.send(InterestResult::Data(data.clone())).is_err() {
                    debug!("[Face {}] Failed to send Data to pending Interest", face_id);
                }
            }
            
            // Always send an event as well
            let event = FaceEvent::DataReceived(data);
            event_sender.lock().await.send(event).await?;
        }
    }
    
    Ok(())
}
