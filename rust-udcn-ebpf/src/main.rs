#![no_std]
#![no_main]
#![allow(nonstandard_style, improper_ctypes)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use memoffset::offset_of;

use rust_udcn_common::types::{PitKey, PitValue, FibKey, FibValue, CsKey, CsValue};

mod bindings;
mod cs;
mod fib;
mod maps;
mod ndn;
mod parser;
mod pit;
mod utils;

use bindings::{
    xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_REDIRECT, XDP_TX},
    EtherHdr, Ipv6Hdr, UdpHdr, ETHER_HDR_SIZE, ETH_P_IPV6, IPPROTO_UDP, IPV6_HDR_SIZE, MAX_NAME_LENGTH,
    NDN_PORT, TLV_TYPE_DATA, TLV_TYPE_INTEREST, UDP_HDR_SIZE,
};

use crate::parser::{parse_ethhdr, parse_ip6hdr, parse_ndn_packet, parse_udphdr, PacketType};
use crate::utils::get_timestamp;

// Define maps for the PIT, FIB, CS, and metrics
#[map(name = "PIT_TABLE")]
static mut PIT_TABLE: LruHashMap<PitKey, PitValue> = LruHashMap::<PitKey, PitValue>::with_max_entries(1024, 0);

#[map(name = "FIB_TABLE")]
static mut FIB_TABLE: HashMap<FibKey, FibValue> = HashMap::<FibKey, FibValue>::with_max_entries(1024, 0);

#[map(name = "CS_TABLE")]
static mut CS_TABLE: LruHashMap<CsKey, CsValue> = LruHashMap::<CsKey, CsValue>::with_max_entries(1024, 0);

#[map(name = "METRICS")]
static mut METRICS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32, 0);

#[xdp]
pub fn ndn_xdp(ctx: XdpContext) -> u32 {
    match try_ndn_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

// Main XDP program logic
fn try_ndn_xdp(ctx: XdpContext) -> Result<u32, ()> {
    // Parse Ethernet header
    let ethhdr: *const EtherHdr = parse_ethhdr(&ctx)?;
    
    // We only care about IPv6 traffic (NDN typically uses IPv6)
    if unsafe { (*ethhdr).h_proto } != ETH_P_IPV6.to_be() {
        return Ok(XDP_PASS);
    }
    
    // Parse IPv6 header
    let ip6hdr: *const Ipv6Hdr = parse_ip6hdr(&ctx, ethhdr)?;
    
    // We only care about UDP traffic
    if unsafe { (*ip6hdr).nexthdr } != IPPROTO_UDP {
        return Ok(XDP_PASS);
    }
    
    // Parse UDP header
    let udphdr: *const UdpHdr = parse_udphdr(&ctx, ip6hdr)?;
    
    // We only care about traffic to/from the NDN port
    let dest_port = u16::from_be(unsafe { (*udphdr).dest });
    let source_port = u16::from_be(unsafe { (*udphdr).source });
    
    if dest_port != NDN_PORT && source_port != NDN_PORT {
        return Ok(XDP_PASS);
    }
    
    // Increment total packets counter
    unsafe {
        if let Some(count) = METRICS.get_ptr_mut(&maps::metrics::PACKETS_TOTAL) {
            *count += 1;
        }
    }
    
    // Parse the NDN packet
    let pkt_type_and_name = match parse_ndn_packet(&ctx, udphdr) {
        Ok(result) => result,
        Err(_) => {
            // Malformed NDN packet, drop it
            return Ok(XDP_DROP);
        }
    };
    
    match pkt_type_and_name.0 {
        PacketType::Interest => {
            // It's an Interest packet, handle it
            unsafe {
                // Increment Interest counter
                if let Some(count) = METRICS.get_ptr_mut(&maps::metrics::INTERESTS_RECEIVED) {
                    *count += 1;
                }
            }
            
            // Extract the name hash and nonce
            let name_hash = pkt_type_and_name.1;
            let nonce = pkt_type_and_name.2;
            
            // Try to find in Content Store first
            match cs::lookup(name_hash) {
                Ok(true) => {
                    // CS hit: this would be handled by userspace which would send the cached data
                    // For now we just count the hit and pass to userspace
                    // In a real implementation, we could potentially craft the Data response here
                    // or attach metadata to inform userspace about the CS hit
                    return Ok(XDP_PASS);
                },
                _ => {
                    // CS miss: check if it's a duplicate Interest by looking in the PIT
                    let pit_key = PitKey {
                        name_hash,
                        name_len: pkt_type_and_name.3, // name_len
                        nonce,
                    };
                    
                    if pit::has_duplicate(&pit_key) {
                        // Duplicate Interest, drop it
                        unsafe {
                            if let Some(count) = METRICS.get_ptr_mut(&maps::metrics::INTERESTS_DUPLICATE) {
                                *count += 1;
                            }
                        }
                        return Ok(XDP_DROP);
                    }
                    
                    // Add to PIT with current timestamp and incoming interface
                    let pit_value = PitValue {
                        arrival_time: get_timestamp(),
                        face_id: ctx.ingress_ifindex() as u16, // Use interface index as face ID
                    };
                    
                    if let Err(_) = pit::add_entry(&pit_key, &pit_value) {
                        // Error adding to PIT, pass to userspace to handle
                        return Ok(XDP_PASS);
                    }
                    
                    unsafe {
                        if let Some(count) = METRICS.get_ptr_mut(&maps::metrics::PIT_INSERTS) {
                            *count += 1;
                        }
                    }
                    
                    // Forward based on FIB
                    match fib::find_next_hop(name_hash) {
                        Some(face_id) => {
                            // FIB hit: we found a route
                            unsafe {
                                if let Some(count) = METRICS.get_ptr_mut(&maps::metrics::FIB_HITS) {
                                    *count += 1;
                                }
                            }
                            
                            // In a real implementation, we would redirect to the face_id
                            // For now, just pass to userspace which will handle forwarding
                            return Ok(XDP_PASS);
                        }
                        None => {
                            // FIB miss: no route found
                            // Pass to userspace which might have routing strategies or fallbacks
                            return Ok(XDP_PASS);
                        }
                    }
                }
            }
        },
        PacketType::Data => {
            // It's a Data packet, handle it
            unsafe {
                // Increment Data counter
                if let Some(count) = METRICS.get_ptr_mut(&maps::metrics::DATA_RECEIVED) {
                    *count += 1;
                }
            }
            
            // Extract the name hash
            let name_hash = pkt_type_and_name.1;
            
            // Check PIT for matching Interest
            if let Ok(true) = pit::has_matching_interest(name_hash) {
                unsafe {
                    if let Some(count) = METRICS.get_ptr_mut(&maps::metrics::PIT_MATCHES) {
                        *count += 1;
                    }
                }
                
                // Add to Content Store
                // In a real implementation, we would extract the content size and TTL
                // For now, use placeholders
                let content_size = 1000; // Placeholder
                let ttl_ms = 60000;      // 1 minute
                
                if let Ok(_) = cs::insert(name_hash, content_size, ttl_ms) {
                    unsafe {
                        if let Some(count) = METRICS.get_ptr_mut(&maps::metrics::CS_INSERTS) {
                            *count += 1;
                        }
                    }
                }
                
                // In a real implementation, we would:
                // 1. Get the list of faces from the PIT that requested this Data
                // 2. Forward the Data to those faces
                // 3. Remove the PIT entries
                
                // For now, pass to userspace which will handle forwarding
                return Ok(XDP_PASS);
            } else {
                // No matching Interest in PIT, drop the Data
                // This is unsolicited Data
                return Ok(XDP_DROP);
            }
        },
        PacketType::Unknown => {
            // Unknown packet type, pass to userspace
            return Ok(XDP_PASS);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
