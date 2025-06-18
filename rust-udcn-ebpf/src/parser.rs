//! Packet parsing utilities for the NDN-XDP program.

use core::mem;
use aya_bpf::{
    bindings::xdp_action,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use crate::ndn;
use crate::maps;
use crate::utils;

/// IPv6 header structure
#[repr(C, packed)]
pub struct Ipv6Header {
    // Version (4 bits), Traffic Class (8 bits), and Flow Label (20 bits)
    pub ver_tc_flow: u32,
    // Payload length
    pub payload_len: u16,
    // Next header type
    pub next_hdr: u8,
    // Hop limit
    pub hop_limit: u8,
    // Source address
    pub src_addr: [u8; 16],
    // Destination address
    pub dst_addr: [u8; 16],
}

/// UDP header structure
#[repr(C, packed)]
pub struct UdpHeader {
    // Source port
    pub src_port: u16,
    // Destination port
    pub dst_port: u16,
    // Length of UDP header and data
    pub length: u16,
    // Checksum
    pub checksum: u16,
}

/// Ethernet header structure
#[repr(C, packed)]
pub struct EtherHeader {
    // Destination MAC address
    pub dst_addr: [u8; 6],
    // Source MAC address
    pub src_addr: [u8; 6],
    // EtherType
    pub eth_type: u16,
}

/// Protocol types
pub const IPPROTO_UDP: u8 = 17;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_HDR_SIZE: usize = mem::size_of::<EtherHeader>();
pub const IPV6_HDR_SIZE: usize = mem::size_of::<Ipv6Header>();
pub const UDP_HDR_SIZE: usize = mem::size_of::<UdpHeader>();

/// NDN default port
pub const NDN_PORT: u16 = 6363;

/// Wrapper around packet data that allows safe parsing
pub struct Packet<'a> {
    ctx: &'a XdpContext,
    eth_offset: usize,
    ipv6_offset: usize,
    udp_offset: usize,
    data_offset: usize,
    data_len: usize,
}

impl<'a> Packet<'a> {
    /// Parse a packet from XDP context
    pub fn parse(ctx: &'a XdpContext) -> Result<Self, ()> {
        let eth_offset = 0;
        
        // Ensure we can read the ethernet header
        let eth_ptr = utils::ptr_at::<EtherHeader>(ctx, eth_offset)?;
        let eth = unsafe { &*eth_ptr };
        
        // Check if this is IPv6
        if u16::from_be(eth.eth_type) != ETH_P_IPV6 {
            return Err(());
        }
        
        let ipv6_offset = eth_offset + ETH_HDR_SIZE;
        
        // Ensure we can read the IPv6 header
        let ipv6_ptr = utils::ptr_at::<Ipv6Header>(ctx, ipv6_offset)?;
        let ipv6 = unsafe { &*ipv6_ptr };
        
        // Check if this is UDP
        if ipv6.next_hdr != IPPROTO_UDP {
            return Err(());
        }
        
        let udp_offset = ipv6_offset + IPV6_HDR_SIZE;
        
        // Ensure we can read the UDP header
        let udp_ptr = utils::ptr_at::<UdpHeader>(ctx, udp_offset)?;
        let udp = unsafe { &*udp_ptr };
        
        // Check if this is on the NDN port
        if u16::from_be(udp.dst_port) != NDN_PORT {
            return Err(());
        }
        
        let data_offset = udp_offset + UDP_HDR_SIZE;
        let data_len = u16::from_be(udp.length) as usize - UDP_HDR_SIZE;
        
        // Ensure data isn't larger than packet
        let packet_end = ctx.data() + ctx.data_end();
        if data_offset + data_len > packet_end as usize {
            return Err(());
        }
        
        Ok(Self {
            ctx,
            eth_offset,
            ipv6_offset,
            udp_offset,
            data_offset,
            data_len,
        })
    }
    
    /// Get ethernet header
    pub fn eth_header(&self) -> Result<&EtherHeader, ()> {
        let eth_ptr = utils::ptr_at::<EtherHeader>(self.ctx, self.eth_offset)?;
        Ok(unsafe { &*eth_ptr })
    }
    
    /// Get IPv6 header
    pub fn ipv6_header(&self) -> Result<&Ipv6Header, ()> {
        let ipv6_ptr = utils::ptr_at::<Ipv6Header>(self.ctx, self.ipv6_offset)?;
        Ok(unsafe { &*ipv6_ptr })
    }
    
    /// Get UDP header
    pub fn udp_header(&self) -> Result<&UdpHeader, ()> {
        let udp_ptr = utils::ptr_at::<UdpHeader>(self.ctx, self.udp_offset)?;
        Ok(unsafe { &*udp_ptr })
    }
    
    /// Get pointer to data
    pub fn data_ptr(&self) -> Result<*const u8, ()> {
        utils::byte_ptr_at(self.ctx, self.data_offset)
    }
    
    /// Get length of data
    pub fn data_len(&self) -> usize {
        self.data_len
    }
}

/// Parse the packet to determine if it's an NDN packet and identify its type
pub fn parse_ndn_packet(packet: &Packet) -> Result<ndn::PacketType, ()> {
    // NDN packets start with a TLV type byte
    let data_ptr = packet.data_ptr()?;
    let data_len = packet.data_len();
    
    if data_len < 1 {
        return Err(());
    }
    
    // Read the first byte, which is the TLV type
    let tlv_type = unsafe { *data_ptr };
    
    match tlv_type {
        ndn::TLV_INTEREST => Ok(ndn::PacketType::Interest),
        ndn::TLV_DATA => Ok(ndn::PacketType::Data),
        _ => Err(()),
    }
}

/// Extract a hash of the name from an NDN packet
/// This is a simplified version that just grabs a few bytes from where
/// the name would be and computes a hash from them
pub fn extract_name_hash(packet: &Packet) -> Option<u32> {
    let data_ptr = match packet.data_ptr() {
        Ok(ptr) => ptr,
        Err(_) => return None,
    };
    
    let data_len = packet.data_len();
    
    if data_len < 10 {
        return None;
    }
    
    // Skip packet type (1 byte) and length (1 byte) to get to name TLV
    // This is a simplification; real parser would navigate the TLV structure
    let name_ptr = unsafe { data_ptr.add(2) };
    
    // Read 4 bytes from after the name TLV type and length
    // Again, this is a simplification
    let name_hash_ptr = unsafe { name_ptr.add(2) as *const u32 };
    let name_hash = unsafe { *name_hash_ptr };
    
    Some(name_hash)
}

/// Extract the nonce from an Interest packet
pub fn extract_nonce(packet: &Packet) -> Option<u32> {
    let data_ptr = match packet.data_ptr() {
        Ok(ptr) => ptr,
        Err(_) => return None,
    };
    
    let data_len = packet.data_len();
    
    if data_len < 15 {
        return None;
    }
    
    // Skip to where the nonce might be
    // In a real implementation, this would parse the TLV structure
    // This is a simplified version that assumes a fixed offset
    let nonce_ptr = unsafe { data_ptr.add(10) as *const u32 };
    let nonce = unsafe { *nonce_ptr };
    
    Some(nonce)
}

/// Extract a face ID based on interface and addresses
pub fn extract_face_id(ctx: &XdpContext) -> Result<maps::FaceId, ()> {
    // In a real implementation, this would use the interface index and addresses
    // to look up or compute a face ID. For now, just use a fixed value.
    Ok(maps::FaceId(1))
}
