//! Error types for the μDCN implementation.

use thiserror::Error;

/// All possible errors that can occur within the μDCN implementation.
#[derive(Error, Debug)]
pub enum Error {
    /// Error related to TLV encoding/decoding.
    #[error("TLV error: {0}")]
    Tlv(String),
    
    /// Error related to NDN packet processing.
    #[error("NDN packet error: {0}")]
    NdnPacket(String),
    
    /// Error related to QUIC transport.
    #[error("QUIC transport error: {0}")]
    QuicTransport(String),
    
    /// Error related to eBPF/XDP operations.
    #[error("eBPF/XDP error: {0}")]
    Ebpf(String),
    
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Other errors
    #[error("Other error: {0}")]
    Other(String),
}
