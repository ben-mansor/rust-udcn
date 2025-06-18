//! Common types and utilities for the micro Data-Centric Networking (μDCN) implementation.
//! 
//! This crate provides shared components used by both the kernel-side eBPF programs
//! and the userspace applications in the μDCN architecture.

pub mod ndn;
pub mod tlv;
pub mod metrics;
pub mod types;
pub mod error;

/// Reexport of common types
pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
