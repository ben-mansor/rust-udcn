//! Map interaction utilities for the XDP program.
//!
//! This module provides abstractions for interacting with eBPF maps
//! from userspace, specifically for the PIT, FIB, and CS maps.

use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, MapData, MapError},
    Bpf,
};
use log::{debug, info, warn};
use rust_udcn_common::{ndn::Name, types::*};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

// Constants for map names matching those in the eBPF program
const PIT_TABLE_NAME: &str = "PIT_TABLE";
const FIB_TABLE_NAME: &str = "FIB_TABLE";
const CS_TABLE_NAME: &str = "CS_TABLE";
const METRICS_MAP_NAME: &str = "METRICS";

// Metric indices must match the eBPF program
const METRIC_PACKETS_TOTAL: u32 = 0;
const METRIC_INTERESTS_RECEIVED: u32 = 1;
const METRIC_DATA_RECEIVED: u32 = 2;
const METRIC_CS_HITS: u32 = 3;
const METRIC_INTERESTS_DUPLICATE: u32 = 4;
const METRIC_PIT_INSERTS: u32 = 5;
const METRIC_FIB_HITS: u32 = 6;
const METRIC_CS_INSERTS: u32 = 7;
const METRIC_PIT_MATCHES: u32 = 8;

/// Wrapper for accessing the PIT (Pending Interest Table) from userspace
pub struct PendingInterestTable {
    /// The underlying eBPF hash map
    map: Arc<RwLock<HashMap<MapData, PitKey, PitValue>>>,
}

impl PendingInterestTable {
    /// Create a new PIT wrapper from a BPF object
    pub fn new(bpf: &mut Bpf) -> Result<Self> {
        let map = bpf.take_map(PIT_TABLE_NAME)
            .context(format!("Failed to find map '{}'", PIT_TABLE_NAME))?;

        let map = map.try_into()?;
        
        Ok(Self {
            map: Arc::new(RwLock::new(map)),
        })
    }

    /// Get a PIT entry by key
    pub async fn get(&self, key: &PitKey) -> Result<Option<PitValue>> {
        let map = self.map.read().await;
        Ok(map.get(key, 0)?)
    }

    /// Insert a PIT entry
    pub async fn insert(&self, key: &PitKey, value: &PitValue) -> Result<()> {
        let mut map = self.map.write().await;
        map.insert(key, value, 0)?;
        Ok(())
    }

    /// Remove a PIT entry
    pub async fn remove(&self, key: &PitKey) -> Result<()> {
        let mut map = self.map.write().await;
        map.remove(key)?;
        Ok(())
    }

    /// Get all entries in the PIT
    /// 
    /// Note: This is not an atomic operation and may not reflect the exact state
    /// of the PIT if concurrent modifications are happening.
    pub async fn get_all_entries(&self) -> Result<Vec<(PitKey, PitValue)>> {
        // This is a simplified approach as we can't directly iterate eBPF maps from userspace
        // In a real implementation, we'd have a more sophisticated approach
        let map = self.map.read().await;
        let mut entries = Vec::new();
        
        // Try to fetch a reasonable number of entries by probing keys
        // This is not a complete solution, just a demonstration
        for name_hash in 0..1000 {
            for name_len in 1..=5 {
                for nonce in 0..5 {
                    let key = PitKey {
                        name_hash: name_hash as u32,
                        name_len,
                        nonce: nonce as u32,
                    };
                    
                    if let Ok(Some(value)) = map.get(&key, 0) {
                        entries.push((key, value));
                    }
                }
            }
        }
        
        Ok(entries)
    }

    /// Count entries in the PIT (approximate)
    pub async fn count_entries(&self) -> Result<usize> {
        let entries = self.get_all_entries().await?;
        Ok(entries.len())
    }
}

/// Wrapper for accessing the FIB (Forwarding Information Base) from userspace
pub struct Fib {
    /// The underlying eBPF hash map
    map: Arc<RwLock<HashMap<MapData, FibKey, FibValue>>>,
}

impl Fib {
    /// Create a new FIB wrapper from a BPF object
    pub fn new(bpf: &mut Bpf) -> Result<Self> {
        let map = bpf.take_map(FIB_TABLE_NAME)
            .context(format!("Failed to find map '{}'", FIB_TABLE_NAME))?;

        let map = map.try_into()?;
        
        Ok(Self {
            map: Arc::new(RwLock::new(map)),
        })
    }

    /// Add a route to the FIB
    pub async fn add_route(&self, name_prefix: &Name, face_id: FaceId, cost: u8) -> Result<()> {
        // Compute a deterministic hash for the name prefix
        let prefix_hash = self.compute_prefix_hash(name_prefix);
        let prefix_len = name_prefix.len() as u8;
        
        let key = FibKey {
            prefix_hash,
            prefix_len,
        };
        
        let value = FibValue { face_id, cost };
        
        let mut map = self.map.write().await;
        map.insert(&key, &value, 0)?;
        
        info!("Added route for prefix {} to face {}", name_prefix, face_id.0);
        
        Ok(())
    }

    /// Remove a route from the FIB
    pub async fn remove_route(&self, name_prefix: &Name) -> Result<()> {
        // Compute the same deterministic hash
        let prefix_hash = self.compute_prefix_hash(name_prefix);
        let prefix_len = name_prefix.len() as u8;
        
        let key = FibKey {
            prefix_hash,
            prefix_len,
        };
        
        let mut map = self.map.write().await;
        map.remove(&key)?;
        
        info!("Removed route for prefix {}", name_prefix);
        
        Ok(())
    }

    /// Get a route from the FIB
    pub async fn get_route(&self, name_prefix: &Name) -> Result<Option<FibValue>> {
        // Compute the same deterministic hash
        let prefix_hash = self.compute_prefix_hash(name_prefix);
        let prefix_len = name_prefix.len() as u8;
        
        let key = FibKey {
            prefix_hash,
            prefix_len,
        };
        
        let map = self.map.read().await;
        match map.get(&key, 0) {
            Ok(value) => Ok(Some(value)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get all entries in the FIB
    pub async fn get_all_entries(&self) -> Result<Vec<(Name, FaceId, u8)>> {
        // This is a simplified placeholder
        // In a real implementation, we'd have a more sophisticated approach
        // to retrieve all entries, possibly with help from the kernel
        unimplemented!("Not yet implemented")
    }

    /// Compute a deterministic hash for a name prefix
    fn compute_prefix_hash(&self, name: &Name) -> u32 {
        // Simple FNV-1a hash
        let mut hash: u32 = 2166136261;
        let prime: u32 = 16777619;

        // Convert name to string for hashing
        let name_str = name.to_string();
        
        for b in name_str.bytes() {
            hash ^= b as u32;
            hash = hash.wrapping_mul(prime);
        }
        
        hash
    }
}

/// Wrapper for accessing the CS (Content Store) from userspace
pub struct ContentStore {
    /// The underlying eBPF hash map
    map: Arc<RwLock<HashMap<MapData, CsKey, CsValue>>>,
}

impl ContentStore {
    /// Create a new CS wrapper from a BPF object
    pub fn new(bpf: &mut Bpf) -> Result<Self> {
        let map = bpf.take_map(CS_TABLE_NAME)
            .context(format!("Failed to find map '{}'", CS_TABLE_NAME))?;

        let map = map.try_into()?;
        
        Ok(Self {
            map: Arc::new(RwLock::new(map)),
        })
    }

    /// Get a CS entry by key
    pub async fn get(&self, key: &CsKey) -> Result<Option<CsValue>> {
        let map = self.map.read().await;
        Ok(map.get(key, 0)?)
    }

    /// Insert a CS entry
    pub async fn insert(&self, key: &CsKey, value: &CsValue) -> Result<()> {
        let mut map = self.map.write().await;
        map.insert(key, value, 0)?;
        Ok(())
    }

    /// Remove a CS entry
    pub async fn remove(&self, key: &CsKey) -> Result<()> {
        let mut map = self.map.write().await;
        map.remove(key)?;
        Ok(())
    }

    /// Clear the entire content store
    pub async fn clear(&self) -> Result<()> {
        // Since we can't directly clear an eBPF map, we would need
        // to remove entries one by one or have a kernel helper
        // This is a placeholder for a real implementation
        debug!("Clearing content store (not fully implemented)");
        Ok(())
    }

    /// Get the CS hit rate
    pub async fn hit_rate(&self, bpf: &Bpf) -> Result<f64> {
        // Get the metrics map to read the hit/miss counters
        let metrics = bpf.map(METRICS_MAP_NAME)
            .context(format!("Failed to find map '{}'", METRICS_MAP_NAME))?;

        let metrics: HashMap<_, u32, u64> = HashMap::try_from(metrics)?;
        
        let hits = metrics.get(&METRIC_CS_HITS, 0).unwrap_or(0);
        let misses = metrics.get(&METRIC_INTERESTS_RECEIVED, 0).unwrap_or(0).saturating_sub(hits);
        
        if hits + misses == 0 {
            return Ok(0.0);
        }
        
        Ok(hits as f64 / (hits + misses) as f64)
    }

    /// Get statistics about the CS
    pub async fn get_stats(&self, bpf: &Bpf) -> Result<ContentStoreStats> {
        let metrics = bpf.map(METRICS_MAP_NAME)
            .context(format!("Failed to find map '{}'", METRICS_MAP_NAME))?;

        let metrics: HashMap<_, u32, u64> = HashMap::try_from(metrics)?;
        
        let hits = metrics.get(&METRIC_CS_HITS, 0).unwrap_or(0);
        let inserts = metrics.get(&METRIC_CS_INSERTS, 0).unwrap_or(0);
        
        // Map capacity is fixed at creation time in the eBPF program
        let capacity = MAX_CS_ENTRIES;
        
        // Size could be measured more accurately but this is a simplification
        let size = inserts.min(capacity as u64);
        
        Ok(ContentStoreStats {
            hits,
            inserts,
            capacity,
            size,
        })
    }
}

/// Statistics about the Content Store
#[derive(Debug, Clone, Copy)]
pub struct ContentStoreStats {
    /// Number of cache hits
    pub hits: u64,
    /// Number of insertions
    pub inserts: u64,
    /// Maximum capacity
    pub capacity: usize,
    /// Current size (approximate)
    pub size: u64,
}
