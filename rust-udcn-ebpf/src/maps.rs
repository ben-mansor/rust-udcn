//! eBPF map definitions for NDN-XDP.
//!
//! This module defines the key and value types for eBPF maps used in the NDN-XDP program.
//! These maps are used to implement the PIT, FIB, and Content Store.

/// Face identifier type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct FaceId(pub u16);

/// A key used for the PIT (Pending Interest Table) map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct PitKey {
    /// Hash of the NDN name
    pub name_hash: u32,
    /// Number of components in the name
    pub name_len: u8,
    /// Nonce value from the Interest
    pub nonce: u32,
}

/// A value stored in the PIT map.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PitValue {
    /// ID of the face where the Interest arrived
    pub face_id: FaceId,
    /// Timestamp when the PIT entry was created
    pub timestamp: u64,
    /// Interest lifetime in milliseconds
    pub lifetime_ms: u32,
    /// Number of components in the name
    pub name_component_count: u8,
}

/// A key used for the FIB (Forwarding Information Base) map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FibKey {
    /// Hash of the NDN name prefix
    pub prefix_hash: u32,
    /// Length of the prefix (in components)
    pub prefix_len: u8,
}

/// A value stored in the FIB map.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FibValue {
    /// ID of the face to forward to
    pub face_id: FaceId,
    /// Cost metric for this route
    pub cost: u8,
}

/// A key used for the CS (Content Store) map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct CsKey {
    /// Hash of the NDN name
    pub name_hash: u32,
    /// Length of the name (in components)
    pub name_len: u8,
}

/// A value stored in the CS map.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CsValue {
    /// Hash of the content for verification
    pub content_hash: u64,
    /// Timestamp when the CS entry was created
    pub timestamp: u64,
    /// Size of the content in bytes
    pub content_size: u32,
    /// TTL in milliseconds
    pub ttl_ms: u32,
}

/// Constants and enumerations related to metrics counters in the metrics map
pub mod metrics {
    /// Indices for metrics in the metrics map
    pub const PACKETS_TOTAL: u32 = 0;
    pub const INTERESTS_RECEIVED: u32 = 1;
    pub const DATA_RECEIVED: u32 = 2;
    pub const CS_HITS: u32 = 3;
    pub const INTERESTS_DUPLICATE: u32 = 4;
    pub const PIT_INSERTS: u32 = 5;
    pub const FIB_HITS: u32 = 6; 
    pub const CS_INSERTS: u32 = 7;
    pub const PIT_MATCHES: u32 = 8;
}
