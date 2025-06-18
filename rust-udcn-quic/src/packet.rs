//! NDN packet encoding/decoding for QUIC transport.
//!
//! This module provides utilities for encoding and decoding NDN packets
//! for transmission over QUIC.

use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{debug, trace};
use rust_udcn_common::ndn::{Data, Interest};

/// Packet types
const PACKET_TYPE_INTEREST: u8 = 0x05;
const PACKET_TYPE_DATA: u8 = 0x06;

/// An NDN packet that can be sent over QUIC
#[derive(Debug, Clone)]
pub enum NdnPacket {
    /// An Interest packet
    Interest(Interest),
    
    /// A Data packet
    Data(Data),
}

impl NdnPacket {
    /// Create a new packet from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(anyhow!("Empty packet"));
        }
        
        // The first byte indicates the packet type in NDN-TLV
        match bytes[0] {
            PACKET_TYPE_INTEREST => {
                let interest = Interest::decode(bytes)?;
                Ok(NdnPacket::Interest(interest))
            }
            PACKET_TYPE_DATA => {
                let data = Data::decode(bytes)?;
                Ok(NdnPacket::Data(data))
            }
            _ => Err(anyhow!("Unknown packet type: {}", bytes[0])),
        }
    }

    /// Convert the packet to bytes for transmission
    pub fn to_bytes(&self) -> Result<Bytes> {
        match self {
            NdnPacket::Interest(interest) => {
                let mut buffer = BytesMut::new();
                interest.encode(&mut buffer)?;
                Ok(buffer.freeze())
            }
            NdnPacket::Data(data) => {
                let mut buffer = BytesMut::new();
                data.encode(&mut buffer)?;
                Ok(buffer.freeze())
            }
        }
    }

    /// Get the name of the packet
    pub fn name(&self) -> String {
        match self {
            NdnPacket::Interest(interest) => interest.name().to_string(),
            NdnPacket::Data(data) => data.name().to_string(),
        }
    }

    /// Get the type of the packet as a string
    pub fn packet_type(&self) -> &'static str {
        match self {
            NdnPacket::Interest(_) => "Interest",
            NdnPacket::Data(_) => "Data",
        }
    }
    
    /// Get the size of the packet in bytes
    pub fn size(&self) -> Result<usize> {
        Ok(self.to_bytes()?.len())
    }
}
