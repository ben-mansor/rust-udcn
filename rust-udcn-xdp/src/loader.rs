//! Loader utilities for the eBPF XDP program.
//!
//! This module provides functions for loading and managing the eBPF XDP program.

use anyhow::{Context, Result};
use aya::{
    programs::{xdp::XdpLinkId, Xdp, XdpFlags},
    Bpf,
};
use log::{debug, error, info, warn};
use std::path::Path;

/// Flags for attaching XDP programs
#[derive(Debug, Clone, Copy)]
pub struct XdpAttachFlags {
    /// Use hardware offload if available
    pub offload: bool,
    /// Enable SKB mode (slower but more compatible)
    pub skb_mode: bool,
}

impl Default for XdpAttachFlags {
    fn default() -> Self {
        Self {
            offload: false,
            skb_mode: false,
        }
    }
}

impl XdpAttachFlags {
    /// Convert to aya's XdpFlags
    pub fn to_aya_flags(&self) -> XdpFlags {
        let mut flags = XdpFlags::default();
        
        if self.offload {
            flags |= XdpFlags::HW_MODE;
        } else if self.skb_mode {
            flags |= XdpFlags::SKB_MODE;
        } else {
            // Default to DRV mode (native XDP)
            flags |= XdpFlags::DRV_MODE;
        }
        
        flags
    }
}

/// Load an eBPF object file from the given path
pub fn load_bpf_object<P: AsRef<Path>>(path: P) -> Result<Bpf> {
    let path = path.as_ref();
    
    debug!("Loading BPF object file: {}", path.display());
    
    let bpf = Bpf::load_file(path)
        .context(format!("Failed to load BPF object file: {}", path.display()))?;
    
    info!("Successfully loaded BPF object file: {}", path.display());
    
    Ok(bpf)
}

/// Load the XDP program from a BPF object
pub fn load_xdp_program<'a>(bpf: &'a mut Bpf, program_name: &str) -> Result<&'a mut Xdp> {
    debug!("Loading XDP program: {}", program_name);
    
    let program = bpf
        .program_mut(program_name)
            .context(format!("Failed to find program '{}'", program_name))?
        .try_into()
            .context(format!("Failed to convert program '{}' to XDP", program_name))?;
    
    info!("Successfully loaded XDP program: {}", program_name);
    
    Ok(program)
}

/// Attach an XDP program to an interface
pub fn attach_xdp_to_interface(
    program: &mut Xdp,
    interface: &str,
    flags: XdpAttachFlags,
) -> Result<XdpLinkId> {
    debug!("Attaching XDP program to interface: {}", interface);
    
    let link_id = program
        .attach(interface, flags.to_aya_flags())
        .context(format!("Failed to attach to interface: {}", interface))?;
    
    info!("Successfully attached XDP program to interface: {}", interface);
    
    Ok(link_id)
}

/// Detach an XDP program from an interface
pub fn detach_xdp_from_interface(program: &mut Xdp, link_id: XdpLinkId) -> Result<()> {
    debug!("Detaching XDP program");
    
    program
        .detach(link_id)
        .context("Failed to detach XDP program")?;
    
    info!("Successfully detached XDP program");
    
    Ok(())
}
