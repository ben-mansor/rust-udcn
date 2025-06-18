//! C struct bindings for use in the eBPF program.
//!
//! This module provides Rust representations of C structs that are used
//! for interacting with the kernel.

// Use core because we're in no_std
use core::mem;

/// XDP metadata structure shared between kernel and user space.
#[repr(C)]
pub struct XdpMd {
    /// Data pointer.
    pub data: u32,
    /// Data end pointer.
    pub data_end: u32,
    /// Data meta pointer.
    pub data_meta: u32,
    /// Ingress interface index.
    pub ingress_ifindex: u32,
    /// Rx queue index.
    pub rx_queue_index: u32,
}

/// Ethernet header structure.
#[repr(C, packed)]
pub struct EtherHdr {
    /// Destination MAC address.
    pub h_dest: [u8; 6],
    /// Source MAC address.
    pub h_source: [u8; 6],
    /// Ethernet type.
    pub h_proto: u16,
}

/// IPv6 header structure.
#[repr(C, packed)]
pub struct Ipv6Hdr {
    /// Version, traffic class, and flow label.
    pub version_tc_flow: u32,
    /// Payload length.
    pub payload_len: u16,
    /// Next header.
    pub nexthdr: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Source address.
    pub saddr: [u8; 16],
    /// Destination address.
    pub daddr: [u8; 16],
}

/// UDP header structure.
#[repr(C, packed)]
pub struct UdpHdr {
    /// Source port.
    pub source: u16,
    /// Destination port.
    pub dest: u16,
    /// Length of UDP header and data.
    pub len: u16,
    /// Checksum.
    pub check: u16,
}

/// Constants for Ethernet protocol values.
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;

/// Constants for IP protocol values.
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// XDP action return codes.
pub mod xdp_action {
    pub const XDP_ABORTED: u32 = 0;
    pub const XDP_DROP: u32 = 1;
    pub const XDP_PASS: u32 = 2;
    pub const XDP_TX: u32 = 3;
    pub const XDP_REDIRECT: u32 = 4;
}

/// Size constants for packet headers.
pub const ETHER_HDR_SIZE: usize = mem::size_of::<EtherHdr>();
pub const IPV6_HDR_SIZE: usize = mem::size_of::<Ipv6Hdr>();
pub const UDP_HDR_SIZE: usize = mem::size_of::<UdpHdr>();

/// NDN default port number.
pub const NDN_PORT: u16 = 6363;

/// RFC8609 defined NDN TLV-TYPE values.
pub const TLV_TYPE_INTEREST: u8 = 0x05;
pub const TLV_TYPE_DATA: u8 = 0x06;
pub const TLV_TYPE_NACK: u8 = 0x03;
pub const TLV_TYPE_NAME: u8 = 0x07;
pub const TLV_TYPE_COMPONENT: u8 = 0x08;

/// Maximum length for an NDN name.
pub const MAX_NAME_LENGTH: usize = 1024;

/// Maximum NDN packet size.
pub const MAX_NDN_PACKET_SIZE: usize = 8800;
