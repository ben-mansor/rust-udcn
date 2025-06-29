//! Userspace XDP library for µDCN (micro Data-Centric Networking)
//! 
//! This crate provides userspace components for loading, managing,
//! and interacting with the eBPF XDP programs in the µDCN architecture.

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, MapData, lru_hash_map::LruHashMap},
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use log::{debug, info, warn};
use rust_udcn_common::{metrics::UdcnMetrics, ndn::Name, types::*};
use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

mod loader;
mod maps;

pub use maps::{ContentStore, Fib, PendingInterestTable};

/// NDN port as defined in RFC8609
pub const NDN_PORT: u16 = 6363;

/// Path to the default eBPF object file
pub const DEFAULT_EBPF_PATH: &str = "rust_udcn_ebpf.o";

/// XDP manager that handles loading and interaction with the XDP eBPF program
pub struct XdpManager {
    /// The loaded BPF program
    bpf: Bpf,
    
    /// The XDP program instance
    program: Option<Xdp>,
    
    /// Metrics for the XDP program
    metrics: Arc<RwLock<UdcnMetrics>>,
    
    /// The PIT (Pending Interest Table)
    pit: Arc<PendingInterestTable>,
    
    /// The FIB (Forwarding Information Base)
    fib: Arc<Fib>,
    
    /// The CS (Content Store)
    cs: Arc<ContentStore>,
    
    /// List of attached network interfaces
    attached_interfaces: Vec<String>,
}

impl XdpManager {
    /// Load the XDP program from the given path or use the embedded program
    pub async fn load_from_embedded() -> Result<Self> {
        // This will include the eBPF object file at compile time
        // The eBPF object compiled by the build script is placed in OUT_DIR
        let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"), "/rust_udcn_ebpf.o"
        )))?;

        // Initialize logging for the BPF program
        if let Err(e) = BpfLogger::init(&mut bpf) {
            warn!("Failed to initialize BPF logger: {}", e);
        }
        
        // Initialize the metrics
        let metrics = Arc::new(RwLock::new(UdcnMetrics::new()));
        
        // Initialize the tables
        let pit = Arc::new(PendingInterestTable::new(&mut bpf)?);
        let fib = Arc::new(Fib::new(&mut bpf)?);
        let cs = Arc::new(ContentStore::new(&mut bpf)?);
        
        Ok(Self {
            bpf,
            program: None,
            metrics,
            pit,
            fib,
            cs,
            attached_interfaces: Vec::new(),
        })
    }

    /// Load the XDP program from a file
    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut bpf = Bpf::load_file(path.as_ref())?;

        // Initialize logging for the BPF program
        if let Err(e) = BpfLogger::init(&mut bpf) {
            warn!("Failed to initialize BPF logger: {}", e);
        }
        
        // Initialize the metrics
        let metrics = Arc::new(RwLock::new(UdcnMetrics::new()));
        
        // Initialize the tables
        let pit = Arc::new(PendingInterestTable::new(&mut bpf)?);
        let fib = Arc::new(Fib::new(&mut bpf)?);
        let cs = Arc::new(ContentStore::new(&mut bpf)?);
        
        Ok(Self {
            bpf,
            program: None,
            metrics,
            pit,
            fib,
            cs,
            attached_interfaces: Vec::new(),
        })
    }

    /// Attach the XDP program to the specified network interface
    pub fn attach(&mut self, interface_name: &str) -> Result<()> {
        // Get the XDP program from the BPF object
        let program: &mut Xdp = self.bpf.program_mut("ndn_xdp")
            .context("Failed to find XDP program 'ndn_xdp'")?
            .try_into()?;

        // Load the program into the kernel
        program.load()?;
        
        // Attach it to the interface
        program.attach(interface_name, XdpFlags::default())
            .context(format!("Failed to attach to interface {}", interface_name))?;
        
        // Store the program instance
        self.program = Some(program.clone());
        
        // Add the interface to our list
        self.attached_interfaces.push(interface_name.to_string());
        
        info!("XDP program attached to interface {}", interface_name);
        
        Ok(())
    }

    /// Detach the XDP program from all interfaces
    pub fn detach_all(&mut self) -> Result<()> {
        if let Some(prog) = self.program.as_mut() {
            for interface in &self.attached_interfaces {
                if let Err(e) = prog.detach(interface) {
                    warn!("Failed to detach from interface {}: {}", interface, e);
                } else {
                    info!("Detached XDP program from interface {}", interface);
                }
            }
            self.attached_interfaces.clear();
        }
        Ok(())
    }

    /// Add a route to the FIB
    pub async fn add_route(&self, name_prefix: &Name, face_id: FaceId, cost: u8) -> Result<()> {
        self.fib.add_route(name_prefix, face_id, cost).await
    }

    /// Remove a route from the FIB
    pub async fn remove_route(&self, name_prefix: &Name) -> Result<()> {
        self.fib.remove_route(name_prefix).await
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> UdcnMetrics {
        self.metrics.read().await.clone()
    }

    /// Get the Pending Interest Table (PIT)
    pub fn pit(&self) -> Arc<PendingInterestTable> {
        Arc::clone(&self.pit)
    }

    /// Get the Forwarding Information Base (FIB)
    pub fn fib(&self) -> Arc<Fib> {
        Arc::clone(&self.fib)
    }

    /// Get the Content Store (CS)
    pub fn cs(&self) -> Arc<ContentStore> {
        Arc::clone(&self.cs)
    }
    
    /// Get a list of attached interfaces
    pub fn attached_interfaces(&self) -> &[String] {
        &self.attached_interfaces
    }
    
    /// Check if the program is attached to any interface
    pub fn is_attached(&self) -> bool {
        !self.attached_interfaces.is_empty()
    }
}
