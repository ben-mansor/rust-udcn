//! Common types shared between userspace and eBPF kernel components.
//!
//! These types are used for communication between the kernel and userspace
//! components via eBPF maps and must be carefully designed to work in both contexts.

use serde::{Deserialize, Serialize};
use std::fmt;
use aya::Pod;
use std::net::Ipv6Addr;

/// Interface identifier type used for identifying network interfaces.
pub type InterfaceId = u32;

/// Maximum length of a face name string.
pub const MAX_FACE_NAME_LEN: usize = 64;

/// Maximum number of entries in the FIB table.
pub const MAX_FIB_ENTRIES: usize = 1024;

/// Maximum number of entries in the PIT table.
pub const MAX_PIT_ENTRIES: usize = 2048;

/// Maximum number of entries in the content store.
pub const MAX_CS_ENTRIES: usize = 4096;

/// Unique identifier for a PIT entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct PitId(pub u32);

impl fmt::Display for PitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PitId({})", self.0)
    }
}

/// Unique identifier for a face.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct FaceId(pub u16);

impl fmt::Display for FaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FaceId({})", self.0)
    }
}

/// Face type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FaceType {
    /// Physical network interface.
    NetDevice = 0,
    /// Internal app face.
    App = 1,
    /// QUIC connection.
    Quic = 2,
}

/// The action to take when processing a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum XdpAction {
    /// Aborts packet processing; packet is dropped.
    Aborted = 0,
    /// Packet is dropped.
    Drop = 1,
    /// Packet passes through to the networking stack.
    Pass = 2,
    /// Packet is TX'd out the same interface it was received on.
    Tx = 3,
    /// Packet is redirected to another interface.
    Redirect = 4,
}

/// Information about a packet that is being forwarded.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ForwardInfo {
    /// The destination IPv6 address.
    pub dst_addr: [u8; 16],
    /// The source IPv6 address.
    pub src_addr: [u8; 16],
    /// The destination port.
    pub dst_port: u16,
    /// The source port.
    pub src_port: u16,
}

impl ForwardInfo {
    /// Create a new ForwardInfo.
    pub fn new(dst_addr: Ipv6Addr, src_addr: Ipv6Addr, dst_port: u16, src_port: u16) -> Self {
        Self {
            dst_addr: dst_addr.octets(),
            src_addr: src_addr.octets(),
            dst_port,
            src_port,
        }
    }

    /// Get the destination IPv6 address.
    pub fn dst_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.dst_addr)
    }

    /// Get the source IPv6 address.
    pub fn src_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.src_addr)
    }
}

/// A key used for the PIT table in the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct PitKey {
    /// Truncated hash of the NDN name
    pub name_hash: u32,
    /// Full name length (in components)
    pub name_len: u8,
    /// Nonce value from the Interest
    pub nonce: u32,
}

/// A value stored in the PIT table in the kernel.
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

/// A key used for the FIB table in the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FibKey {
    /// Truncated hash of the NDN name prefix
    pub prefix_hash: u32,
    /// Length of the prefix (in components)
    pub prefix_len: u8,
}

/// A value stored in the FIB table in the kernel.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FibValue {
    /// ID of the face to forward to
    pub face_id: FaceId,
    /// Cost metric for this route
    pub cost: u8,
}

/// A key used for the content store in the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct CsKey {
    /// Truncated hash of the NDN name
    pub name_hash: u32,
    /// Full name length (in components)
    pub name_len: u8,
}

/// A value stored in the content store in the kernel.
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

unsafe impl Pod for ForwardInfo {}
unsafe impl Pod for PitKey {}
unsafe impl Pod for PitValue {}
unsafe impl Pod for FibKey {}
unsafe impl Pod for FibValue {}
unsafe impl Pod for CsKey {}
unsafe impl Pod for CsValue {}
unsafe impl Pod for PitId {}
unsafe impl Pod for FaceId {}
