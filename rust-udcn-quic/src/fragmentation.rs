//! Fragmentation and reassembly for NDN packets over QUIC.
//!
//! This module provides utilities for fragmenting large NDN packets
//! into smaller chunks for transmission over QUIC, and reassembling
//! them on the receiving end.

use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use log::trace;
use std::collections::VecDeque;

/// Fragment a large packet into smaller chunks
pub fn fragment_packet(packet: &[u8], fragment_size: usize) -> Vec<Bytes> {
    let mut fragments = Vec::new();
    let mut offset = 0;
    
    while offset < packet.len() {
        let end = std::cmp::min(offset + fragment_size, packet.len());
        let fragment = Bytes::copy_from_slice(&packet[offset..end]);
        fragments.push(fragment);
        offset = end;
    }
    
    trace!("Fragmented packet of size {} into {} fragments", packet.len(), fragments.len());
    
    fragments
}

/// Reassemble fragments into a complete packet
pub fn assemble_fragments(fragments: VecDeque<Bytes>) -> Result<Bytes> {
    // Calculate the total size
    let total_size: usize = fragments.iter().map(|f| f.len()).sum();
    
    if total_size == 0 {
        return Err(anyhow!("No fragments to assemble"));
    }
    
    // Create a buffer large enough for all fragments
    let mut buffer = BytesMut::with_capacity(total_size);
    
    // Add all fragments to the buffer
    for fragment in fragments {
        buffer.extend_from_slice(&fragment);
    }
    
    trace!("Assembled {} bytes from fragments", buffer.len());
    
    Ok(buffer.freeze())
}

/// Check if a packet needs to be fragmented
pub fn needs_fragmentation(packet_size: usize, mtu: usize) -> bool {
    packet_size > mtu
}

/// Calculate the number of fragments needed
pub fn calculate_fragment_count(packet_size: usize, fragment_size: usize) -> usize {
    (packet_size + fragment_size - 1) / fragment_size
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fragmentation_and_reassembly() {
        // Create a test packet
        let packet = vec![0u8; 10000];
        
        // Fragment it
        let fragments = fragment_packet(&packet, 1000);
        
        // Check that we have the right number of fragments
        assert_eq!(fragments.len(), 10);
        
        // Reassemble the fragments
        let reassembled = assemble_fragments(fragments.into()).unwrap();
        
        // Check that the reassembled packet matches the original
        assert_eq!(reassembled.len(), packet.len());
        assert_eq!(reassembled, Bytes::from(packet));
    }
    
    #[test]
    fn test_needs_fragmentation() {
        assert!(needs_fragmentation(1500, 1200));
        assert!(!needs_fragmentation(1000, 1200));
    }
    
    #[test]
    fn test_calculate_fragment_count() {
        assert_eq!(calculate_fragment_count(1000, 1000), 1);
        assert_eq!(calculate_fragment_count(1001, 1000), 2);
        assert_eq!(calculate_fragment_count(2500, 1000), 3);
    }
}
