//! Utility functions for eBPF programs.
//!
//! This module provides helper functions for common operations in eBPF programs
//! such as pointer manipulation and boundary checking.

use aya_bpf::programs::XdpContext;

/// Get a pointer to a type T at a given offset in the packet data.
///
/// This function verifies that the entire object of type T can be
/// safely accessed within the packet boundaries.
#[inline]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data() as usize + offset;
    let end = start + core::mem::size_of::<T>();
    
    if end > ctx.data_end() as usize {
        return Err(());
    }
    
    Ok(start as *const T)
}

/// Get a mutable pointer to a type T at a given offset in the packet data.
///
/// This function verifies that the entire object of type T can be
/// safely accessed within the packet boundaries.
#[inline]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data() as usize + offset;
    let end = start + core::mem::size_of::<T>();
    
    if end > ctx.data_end() as usize {
        return Err(());
    }
    
    Ok(start as *mut T)
}

/// Get a pointer to a byte at a given offset in the packet data.
#[inline]
pub fn byte_ptr_at(ctx: &XdpContext, offset: usize) -> Result<*const u8, ()> {
    let addr = ctx.data() as usize + offset;
    
    if addr >= ctx.data_end() as usize {
        return Err(());
    }
    
    Ok(addr as *const u8)
}

/// Get a mutable pointer to a byte at a given offset in the packet data.
#[inline]
pub fn byte_ptr_at_mut(ctx: &XdpContext, offset: usize) -> Result<*mut u8, ()> {
    let addr = ctx.data() as usize + offset;
    
    if addr >= ctx.data_end() as usize {
        return Err(());
    }
    
    Ok(addr as *mut u8)
}

/// Check if a memory region is within the packet bounds.
#[inline]
pub fn check_bounds(ctx: &XdpContext, start: usize, len: usize) -> Result<(), ()> {
    let data_start = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;
    
    let region_start = data_start + start;
    let region_end = region_start + len;
    
    if region_start > data_end || region_end > data_end || region_end < region_start {
        return Err(());
    }
    
    Ok(())
}

/// Get the current timestamp in milliseconds.
///
/// This is a simplified version that just returns the current
/// monotonic clock value from bpf_ktime_get_ns() divided by 1_000_000.
#[inline]
pub fn get_timestamp() -> u64 {
    unsafe {
        // bpf_ktime_get_ns() / 1_000_000 to get milliseconds
        let ns = core::arch::asm!("r0 = ktime_get_ns()", out("r0") _, options(nostack, nomem));
        let ns: u64;
        core::arch::asm!("", out("r0") ns, options(pure, nomem, nostack));
        ns / 1_000_000
    }
}

/// Extract a u16 from two bytes in network byte order (big endian).
#[inline]
pub fn extract_be_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 1 >= data.len() {
        return None;
    }
    
    Some(((data[offset] as u16) << 8) | (data[offset + 1] as u16))
}

/// Extract a u32 from four bytes in network byte order (big endian).
#[inline]
pub fn extract_be_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 3 >= data.len() {
        return None;
    }
    
    Some(
        ((data[offset] as u32) << 24) |
        ((data[offset + 1] as u32) << 16) |
        ((data[offset + 2] as u32) << 8) |
        (data[offset + 3] as u32)
    )
}
