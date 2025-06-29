//! Content Store (CS) operations.
//!
//! This module handles operations for the Content Store,
//! which caches Data packets to satisfy future matching Interests.

use aya_ebpf::maps::LruHashMap;

use crate::maps::{CsKey, CsValue};
use crate::maps::metrics;
use crate::utils;

// Reference to the CS table map
extern "C" {
    #[link_name = "CS_TABLE"]
    static mut CS_TABLE: LruHashMap<CsKey, CsValue>;
    
    #[link_name = "METRICS"]
    static mut METRICS: aya_ebpf::maps::HashMap<u32, u64>;
}

/// Check if a Data packet is in the Content Store.
///
/// Given a name hash, check if a matching Data packet exists in the CS.
pub fn lookup(name_hash: u32) -> Result<bool, ()> {
    let key = CsKey {
        name_hash,
        name_len: 0, // Simplified for now
    };
    
    let found = unsafe { CS_TABLE.get(&key).is_some() };
    if found {
        // Increment CS hit counter
        unsafe {
            if let Some(counter) = METRICS.get_ptr_mut(&metrics::CS_HITS) {
                *counter += 1;
            }
        }
    }
    
    Ok(found)
}

/// Add a Data packet to the Content Store.
///
/// Given a name hash and content details, add to the CS.
pub fn insert(name_hash: u32, content_size: u32, ttl_ms: u32) -> Result<(), ()> {
    let key = CsKey {
        name_hash,
        name_len: 0, // Simplified for now
    };
    
    let value = CsValue {
        content_hash: 0, // Would compute a hash in a real implementation
        timestamp: utils::get_timestamp(),
        content_size,
        ttl_ms,
    };
    
    unsafe {
        CS_TABLE.insert(&key, &value, 0).map_err(|_| ())?;
        
        // Increment CS insert counter
        if let Some(counter) = METRICS.get_ptr_mut(&metrics::CS_INSERTS) {
            *counter += 1;
        }
    }
    
    Ok(())
}

/// Check if a CS entry has expired.
///
/// An entry is expired if the current time is greater than the creation time
/// plus the TTL.
pub fn is_entry_expired(entry: &CsValue) -> bool {
    let current_time = utils::get_timestamp();
    current_time > entry.timestamp + entry.ttl_ms as u64
}

/// Clean up expired CS entries.
///
/// In a real implementation, this would be handled by a helper program or
/// by the userspace component, as iterating over eBPF maps is difficult.
pub fn cleanup_expired_entries() -> u32 {
    // Simplified implementation since we can't iterate over maps in eBPF easily
    0 // Placeholder value
}

/// Get a Data packet from the Content Store.
///
/// Given a name hash, retrieve the corresponding Data packet if it exists.
/// In this simplified version, we just check if it exists and doesn't handle 
/// the actual data retrieval which would be done by the userspace component.
pub fn get_data(name_hash: u32) -> Option<CsValue> {
    let key = CsKey {
        name_hash,
        name_len: 0, // Simplified for now
    };
    
    unsafe {
        CS_TABLE.get(&key).copied()
    }
}
