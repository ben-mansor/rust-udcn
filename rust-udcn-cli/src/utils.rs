//! Utility functions for the µDCN CLI

use anyhow::Result;
use log::info;
use std::time::{Duration, Instant};

/// Format a duration as a human-readable string
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    
    if total_secs < 60 {
        format!("{}.{:03}s", total_secs, duration.subsec_millis())
    } else if total_secs < 3600 {
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{}m {}s", mins, secs)
    } else {
        let hours = total_secs / 3600;
        let mins = (total_secs % 3600) / 60;
        let secs = total_secs % 60;
        format!("{}h {}m {}s", hours, mins, secs)
    }
}

/// Format a byte size as a human-readable string
pub fn format_bytes(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;
    
    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    }
}

/// Simple timer for measuring operations
pub struct Timer {
    start: Instant,
    operation: String,
}

impl Timer {
    /// Create a new timer for the specified operation
    pub fn new(operation: &str) -> Self {
        info!("Starting operation: {}", operation);
        Self {
            start: Instant::now(),
            operation: operation.to_string(),
        }
    }
    
    /// Measure the elapsed time and print a log message
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
    
    /// Get the elapsed time as a formatted string
    pub fn elapsed_str(&self) -> String {
        format_duration(self.elapsed())
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        info!(
            "Operation '{}' completed in {}",
            self.operation,
            format_duration(self.elapsed())
        );
    }
}

/// Print a section header in the CLI output
pub fn print_header(title: &str) {
    let separator = "=".repeat(title.len());
    println!("\n{}", title);
    println!("{}", separator);
}
