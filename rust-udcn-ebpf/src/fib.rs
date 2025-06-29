//! FIB (Forwarding Information Base) operations.
//!
//! This module handles operations for the Forwarding Information Base,
//! which maps name prefixes to next-hop faces.

use aya_ebpf::maps::HashMap;

use crate::maps::{FibKey, FibValue, FaceId};

// Reference to the FIB table map
extern "C" {
    #[link_name = "FIB_TABLE"]
    static mut FIB_TABLE: HashMap<FibKey, FibValue>;
    
    #[link_name = "METRICS"]
    static mut METRICS: aya_ebpf::maps::HashMap<u32, u64>;
}

/// Longest prefix match in the FIB.
///
/// Given a name hash, find the FIB entry with the longest matching prefix.
/// Returns the face ID of the next hop if found.
pub fn longest_prefix_match(name_hash: u32) -> Result<FaceId, ()> {
    let mut best_match: Option<(FibValue, u8)> = None;
    
    // In eBPF, we can't dynamically iterate through map entries.
    // For simplicity, we'll try different prefix lengths from longest to shortest.
    // A real implementation would use more sophisticated techniques.
    for prefix_len in (0..=16).rev() {
        let key = FibKey {
            prefix_hash: name_hash,
            prefix_len,
        };
        
        unsafe {
            if let Some(value) = FIB_TABLE.get(&key) {
                // If we find a match, we update best_match if this is longer than previous matches
                if best_match.is_none() || prefix_len > best_match.as_ref().unwrap().1 {
                    best_match = Some((*value, prefix_len));
                }
            }
        }
    }
    
    // Return the face ID of the best match if found
    if let Some((value, _)) = best_match {
        Ok(value.face_id)
    } else {
        Err(())
    }
}

/// Check if a FIB entry exists.
///
/// Given a FIB key, check if a corresponding entry exists.
pub fn has_entry(key: &FibKey) -> bool {
    unsafe {
        FIB_TABLE.get(key).is_some()
    }
}

/// Count all FIB entries.
///
/// This is a simplified approximation since eBPF doesn't support map iteration.
/// In a real implementation, this would be handled by user space.
pub fn count_entries() -> u32 {
    // Simplified version since we can't iterate over maps in eBPF easily
    // In a real implementation, this would be tracked separately
    42 // Placeholder value
}

/// Find the next hop face for a given name hash.
///
/// This is the main forwarding function that takes a name hash and returns
/// the face ID to forward to.
pub fn find_next_hop(name_hash: u32) -> Option<FaceId> {
    longest_prefix_match(name_hash).ok()
}
