//! PIT (Pending Interest Table) operations.
//!
//! This module handles operations for the Pending Interest Table,
//! which tracks Interest packets that are waiting for matching Data.

use aya_ebpf::maps::LruHashMap;

use crate::maps::{PitKey, PitValue};
use crate::utils;
use crate::maps::metrics;

/// Max number of faces to check when finding matching interests
const MAX_FACE_CHECK: usize = 8;

// Reference to the PIT table map
extern "C" {
    #[link_name = "PIT_TABLE"]
    static mut PIT_TABLE: LruHashMap<PitKey, PitValue>;
    
    #[link_name = "METRICS"]
    static mut METRICS: aya_ebpf::maps::HashMap<u32, u64>;
}

/// Clean up expired PIT entries.
///
/// Iterates through PIT entries and removes those that have expired.
/// Returns the number of entries removed.
pub fn cleanup_expired_entries() -> Result<u32, ()> {
    let current_time = utils::get_timestamp();
    let mut removed = 0;

    // This is a simplification since iterating over maps in eBPF is difficult
    // In a real implementation, this would be handled differently (e.g., using a helper program)
    // or by having the userspace component periodically clean up expired entries.

    Ok(removed)
}

/// Find matching PIT entries for a Data packet.
///
/// Given a name hash, find all PIT entries with the same name hash
/// and return whether any match was found.
pub fn find_matching_interests(name_hash: u32) -> Result<bool, ()> {
    let mut found_match = false;
    
    // Since iterating over eBPF maps is tricky, we'll simulate it with a simplified approach
    // We'll loop through a few potential PIT keys with varying nonces
    for nonce in 0..MAX_FACE_CHECK {
        let key = PitKey {
            name_hash,
            name_len: 0, // Simplified for now
            nonce: nonce as u32,
        };
        
        unsafe {
            if let Some(_value) = PIT_TABLE.get(&key) {
                found_match = true;
                
                // Remove the matching PIT entry since it's been satisfied
                PIT_TABLE.remove(&key).unwrap_or(());
                
                // Increment PIT match counter
                if let Some(counter) = METRICS.get_ptr_mut(&metrics::PIT_MATCHES) {
                    *counter += 1;
                }
                
                // In a real implementation, we would check all faces that requested
                // this Interest and forward the Data to them
            }
        }
    }
    
    Ok(found_match)
}

/// Check if a PIT entry has expired.
///
/// An entry is expired if the current time is greater than the creation time
/// plus the lifetime.
pub fn is_pit_entry_expired(entry: &PitValue) -> bool {
    let current_time = utils::get_timestamp();
    current_time > entry.timestamp + entry.lifetime_ms as u64
}

/// Add a new PIT entry.
///
/// Adds a new entry to the PIT with the given key and value.
pub fn add_pit_entry(key: &PitKey, value: &PitValue) -> Result<(), ()> {
    unsafe {
        PIT_TABLE.insert(key, value, 0).map_err(|_| ())?;
    }
    Ok(())
}

/// Convenience wrapper for adding a PIT entry.
///
/// This function exists for compatibility with older code that expected
/// `add_entry` to be available.  It simply forwards to [`add_pit_entry`].
pub fn add_entry(key: &PitKey, value: &PitValue) -> Result<(), ()> {
    add_pit_entry(key, value)
}

/// Check if a given PIT key already exists.
///
/// This is used to detect duplicate Interests.
pub fn has_duplicate(key: &PitKey) -> bool {
    unsafe { PIT_TABLE.get(key).is_some() }
}

/// Wrapper for [`find_matching_interests`].
///
/// Returns `true` if a Data packet with the provided name hash matches
/// an Interest in the PIT.
pub fn has_matching_interest(name_hash: u32) -> Result<bool, ()> {
    find_matching_interests(name_hash)
}

/// Get the face ID for a PIT entry.
///
/// Given a PIT key, return the face ID from the corresponding value.
pub fn get_pit_face_id(key: &PitKey) -> Result<crate::maps::FaceId, ()> {
    unsafe {
        if let Some(value) = PIT_TABLE.get(key) {
            Ok(value.face_id)
        } else {
            Err(())
        }
    }
}
