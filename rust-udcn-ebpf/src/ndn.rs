//! NDN-related definitions for use in eBPF programs.
//!
//! These are simplified versions of the NDN structures from the common crate
//! adapted for the constraints of the eBPF environment.

/// TLV (Type-Length-Value) constants for NDN packet processing
pub const TLV_INTEREST: u8 = 0x05;
pub const TLV_DATA: u8 = 0x06;
pub const TLV_NACK: u8 = 0x03;
pub const TLV_NAME: u8 = 0x07;
pub const TLV_COMPONENT: u8 = 0x08;
pub const TLV_NONCE: u8 = 0x0A;
pub const TLV_META_INFO: u8 = 0x14;
pub const TLV_CONTENT: u8 = 0x15;
pub const TLV_INTEREST_LIFETIME: u8 = 0x0C;

/// NDN packet types supported by the XDP program
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    /// Interest packet
    Interest,
    /// Data packet
    Data,
    /// NACK packet
    Nack,
}

/// Maximum length of an NDN name in bytes when encoded
pub const MAX_NAME_LENGTH: usize = 1024;

/// Maximum number of components in an NDN name
pub const MAX_NAME_COMPONENTS: usize = 16;

/// Maximum size of an NDN packet
pub const MAX_NDN_PACKET_SIZE: usize = 8800;

/// eBPF-safe function to compute a hash of an NDN name
/// 
/// Since we can't use string operations and have limited functionality in eBPF,
/// this is a simplified version that uses a basic FNV-1a hash algorithm
pub fn compute_name_hash(data: &[u8], len: usize) -> u32 {
    let mut hash: u32 = 2166136261; // FNV-1a offset basis
    let prime: u32 = 16777619;      // FNV prime

    let mut i = 0;
    while i < len && i < data.len() {
        hash ^= data[i] as u32;
        hash = hash.wrapping_mul(prime);
        i += 1;
    }
    
    hash
}

/// A highly simplified TLV parser suitable for eBPF
/// 
/// This function takes a buffer and returns the TLV type and the offset
/// to the value portion of the TLV.
pub fn parse_tlv(data: &[u8], offset: usize) -> Option<(u8, usize, usize)> {
    if offset >= data.len() || data.len() - offset < 2 {
        return None;
    }

    let tlv_type = data[offset];
    let len_byte = data[offset + 1];
    
    let (length, value_offset) = if len_byte < 253 {
        (len_byte as usize, offset + 2)
    } else if len_byte == 253 {
        if data.len() - offset < 4 {
            return None;
        }
        let len = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
        (len, offset + 4)
    } else {
        // Unsupported length encoding for eBPF
        return None;
    };
    
    if value_offset + length > data.len() {
        return None;
    }
    
    Some((tlv_type, value_offset, length))
}
