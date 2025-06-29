//! eBPF kernel components for μDCN (micro Data-Centric Networking)
//! 
//! This crate provides eBPF programs for XDP packet processing in the μDCN architecture.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use memoffset::offset_of;

// Use our common code with no_std compatibility
mod bindings;
mod ndn;
mod maps;
mod parser;
mod pit;
mod fib;
mod utils;

// Define map sizes
const MAX_PIT_ENTRIES: usize = 2048;
const MAX_FIB_ENTRIES: usize = 1024;
const MAX_CS_ENTRIES: usize = 4096;

// Create eBPF maps
#[map(name = "PIT_TABLE")]
static mut PIT_TABLE: LruHashMap<maps::PitKey, maps::PitValue> =
    LruHashMap::<maps::PitKey, maps::PitValue>::with_max_entries(MAX_PIT_ENTRIES as u32, 0);

#[map(name = "FIB_TABLE")]
static mut FIB_TABLE: HashMap<maps::FibKey, maps::FibValue> =
    HashMap::<maps::FibKey, maps::FibValue>::with_max_entries(MAX_FIB_ENTRIES as u32, 0);

#[map(name = "CS_TABLE")]
static mut CS_TABLE: LruHashMap<maps::CsKey, maps::CsValue> =
    LruHashMap::<maps::CsKey, maps::CsValue>::with_max_entries(MAX_CS_ENTRIES as u32, 0);

#[map(name = "METRICS")]
static mut METRICS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32, 0);

/// XDP program entry point for NDN packet processing
#[xdp]
pub fn ndn_xdp(ctx: XdpContext) -> u32 {
    match try_ndn_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Main NDN XDP packet processing logic
fn try_ndn_xdp(ctx: XdpContext) -> Result<u32, ()> {
    // Basic packet parser
    let packet = parser::Packet::parse(&ctx)?;

    // Increment the packet counter
    unsafe {
        let counter = METRICS.get_ptr_mut(&0).ok_or(())?;
        *counter += 1;
    }

    // Check if this is a NDN packet and what type it is
    match parser::parse_ndn_packet(&packet) {
        Ok(ndn::PacketType::Interest) => {
            process_interest(&ctx, packet)
        }
        Ok(ndn::PacketType::Data) => {
            process_data(&ctx, packet)
        }
        _ => {
            // Not an NDN packet or not a supported type, pass it up the stack
            Ok(xdp_action::XDP_PASS)
        }
    }
}

/// Process an Interest packet
fn process_interest(ctx: &XdpContext, packet: parser::Packet) -> Result<u32, ()> {
    unsafe {
        // Increment interest counter
        let counter = METRICS.get_ptr_mut(&1).ok_or(())?;
        *counter += 1;
    }

    // Parse name from Interest packet
    let name_hash = match parser::extract_name_hash(&packet) {
        Some(hash) => hash,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // Check the CS (Content Store) for cached data
    let cs_key = maps::CsKey {
        name_hash,
        name_len: 0, // Simplified for now
    };

    unsafe {
        if let Some(_cs_value) = CS_TABLE.get(&cs_key) {
            // Found in CS! In a full implementation, would retrieve and return the data
            // For now, just increment the CS hit counter
            let counter = METRICS.get_ptr_mut(&3).ok_or(())?;
            *counter += 1;
            
            // In real implementation would return cached data
            // For now just pass up to userspace to handle
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // CS miss, check PIT for duplicate Interest
    // Extract nonce from Interest
    let nonce = parser::extract_nonce(&packet).unwrap_or(0);

    let pit_key = maps::PitKey {
        name_hash,
        name_len: 0, // Simplified for now
        nonce,
    };

    // Check if in PIT
    unsafe {
        if PIT_TABLE.get(&pit_key).is_some() {
            // Duplicate Interest, drop
            let counter = METRICS.get_ptr_mut(&4).ok_or(())?;
            *counter += 1;
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // New Interest, add to PIT
    let face_id = parser::extract_face_id(&ctx)?;
    let pit_value = maps::PitValue {
        face_id,
        timestamp: utils::get_timestamp(),
        lifetime_ms: 4000, // 4 seconds default
        name_component_count: 0, // Simplified for now
    };

    unsafe {
        PIT_TABLE.insert(&pit_key, &pit_value, 0).map_err(|_| ())?;
        
        // Increment PIT insert counter
        let counter = METRICS.get_ptr_mut(&5).ok_or(())?;
        *counter += 1;
    }

    // Check FIB for forwarding
    let fib_key = maps::FibKey {
        prefix_hash: name_hash, // Simplified lookup for now 
        prefix_len: 0,
    };

    unsafe {
        if let Some(_fib_value) = FIB_TABLE.get(&fib_key) {
            // Found in FIB! In full implementation, would forward to face
            // For now, just increment FIB hit counter
            let counter = METRICS.get_ptr_mut(&6).ok_or(())?;
            *counter += 1;
            
            // Pass up to userspace to handle the forwarding
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // No matching FIB entry, pass to userspace for further processing
    Ok(xdp_action::XDP_PASS)
}

/// Process a Data packet
fn process_data(ctx: &XdpContext, packet: parser::Packet) -> Result<u32, ()> {
    unsafe {
        // Increment data counter
        let counter = METRICS.get_ptr_mut(&2).ok_or(())?;
        *counter += 1;
    }

    // Parse name from Data packet
    let name_hash = match parser::extract_name_hash(&packet) {
        Some(hash) => hash,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // Check PIT for matching Interest
    let pit_matched = pit::find_matching_interests(name_hash)?;
    
    if !pit_matched {
        // No matching PIT entry, unsolicited data, drop
        return Ok(xdp_action::XDP_DROP);
    }

    // Add to CS for future Interest matching
    let cs_key = maps::CsKey {
        name_hash,
        name_len: 0, // Simplified for now
    };
    
    let cs_value = maps::CsValue {
        content_hash: 0, // Would calculate content hash in real implementation
        timestamp: utils::get_timestamp(),
        content_size: packet.data_len() as u32,
        ttl_ms: 10000, // 10 seconds default
    };

    unsafe {
        CS_TABLE.insert(&cs_key, &cs_value, 0).map_err(|_| ())?;
        
        // Increment CS insert counter
        let counter = METRICS.get_ptr_mut(&7).ok_or(())?;
        *counter += 1;
    }

    // Pass to userspace for full processing
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
