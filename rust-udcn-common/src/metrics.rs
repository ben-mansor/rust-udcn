//! Metrics collection and reporting for μDCN.
//!
//! This module provides utilities for tracking and reporting performance metrics
//! across both userspace and kernel components.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// A simple counter that can be incremented atomically.
#[derive(Debug)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    /// Creates a new counter with an initial value of 0.
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    /// Increments the counter by 1.
    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the counter by the given value.
    pub fn add(&self, value: u64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }

    /// Returns the current value of the counter.
    pub fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Resets the counter to 0.
    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// A gauge for tracking a value that can go up and down.
#[derive(Debug)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    /// Creates a new gauge with an initial value of 0.
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    /// Sets the gauge to the given value.
    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    /// Increments the gauge by 1.
    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the gauge by 1.
    pub fn decrement(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    /// Returns the current value of the gauge.
    pub fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

/// A histogram for tracking distribution of values.
#[derive(Debug)]
pub struct Histogram {
    /// Counts of values in each bucket.
    buckets: Vec<AtomicU64>,
    /// Bucket boundaries.
    boundaries: Vec<u64>,
    /// Count of values below the minimum boundary.
    underflow: AtomicU64,
    /// Count of values above the maximum boundary.
    overflow: AtomicU64,
    /// Sum of all observed values.
    sum: AtomicU64,
    /// Count of all observed values.
    count: AtomicU64,
}

impl Histogram {
    /// Creates a new histogram with the given bucket boundaries.
    pub fn new(boundaries: Vec<u64>) -> Self {
        let num_buckets = boundaries.len();
        let buckets = (0..num_buckets)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>();

        Self {
            buckets,
            boundaries,
            underflow: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Creates a new histogram with exponentially distributed bucket boundaries.
    pub fn exponential(min: u64, max: u64, bucket_count: usize) -> Self {
        assert!(min < max);
        assert!(bucket_count > 1);

        let factor = (max as f64 / min as f64).powf(1.0 / (bucket_count as f64 - 1.0));
        let mut boundaries = Vec::with_capacity(bucket_count);
        let mut value = min;

        for _ in 0..bucket_count {
            boundaries.push(value);
            value = (value as f64 * factor).ceil() as u64;
        }

        Self::new(boundaries)
    }

    /// Observes a value, incrementing the appropriate bucket.
    pub fn observe(&self, value: u64) {
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        if value < self.boundaries[0] {
            self.underflow.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let mut bucket_idx = self.boundaries.len();
        for (idx, &boundary) in self.boundaries.iter().enumerate() {
            if value <= boundary {
                bucket_idx = idx;
                break;
            }
        }

        if bucket_idx < self.buckets.len() {
            self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
        } else {
            self.overflow.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the average of all observed values.
    pub fn average(&self) -> f64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.sum.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Returns bucket counts as a histogram.
    pub fn counts(&self) -> Vec<(u64, u64)> {
        self.boundaries
            .iter()
            .zip(self.buckets.iter())
            .map(|(&boundary, bucket)| (boundary, bucket.load(Ordering::Relaxed)))
            .collect()
    }

    /// Total number of observations.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Sum of all observed values.
    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }
}

/// A timer for measuring durations.
#[derive(Debug)]
pub struct Timer {
    /// Start time of the current measurement.
    start: Option<Instant>,
    /// Histogram for recording measurements.
    histogram: Histogram,
}

impl Timer {
    /// Creates a new timer with default histogram buckets in microseconds.
    pub fn new() -> Self {
        // Default buckets: 10us, 100us, 1ms, 10ms, 100ms, 1s, 10s
        let boundaries = vec![10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000];
        Self {
            start: None,
            histogram: Histogram::new(boundaries),
        }
    }

    /// Creates a new timer with custom histogram buckets.
    pub fn with_buckets(boundaries: Vec<u64>) -> Self {
        Self {
            start: None,
            histogram: Histogram::new(boundaries),
        }
    }

    /// Starts the timer.
    pub fn start(&mut self) {
        self.start = Some(Instant::now());
    }

    /// Stops the timer and records the duration.
    pub fn stop(&mut self) -> Duration {
        if let Some(start) = self.start.take() {
            let elapsed = start.elapsed();
            let micros = elapsed.as_micros() as u64;
            self.histogram.observe(micros);
            elapsed
        } else {
            Duration::from_secs(0)
        }
    }

    /// Returns the histogram of recorded durations.
    pub fn histogram(&self) -> &Histogram {
        &self.histogram
    }
}

/// Package of metrics for the μDCN implementation.
#[derive(Debug, Default)]
pub struct UdcnMetrics {
    // Packet processing metrics
    pub interests_received: Counter,
    pub interests_satisfied: Counter,
    pub interests_timed_out: Counter,
    pub interests_forwarded: Counter,
    pub data_received: Counter,
    pub data_sent: Counter,
    
    // Cache metrics
    pub cs_hits: Counter,
    pub cs_misses: Counter,
    pub cs_inserts: Counter,
    pub cs_evictions: Counter,
    pub cs_size: Gauge,
    
    // PIT metrics
    pub pit_inserts: Counter,
    pub pit_hits: Counter,
    pub pit_misses: Counter,
    pub pit_expirations: Counter,
    pub pit_size: Gauge,
    
    // FIB metrics
    pub fib_hits: Counter,
    pub fib_misses: Counter,
    pub fib_size: Gauge,
    
    // Performance metrics
    pub interest_processing_time: Timer,
    pub data_processing_time: Timer,
    
    // Transport metrics
    pub bytes_received: Counter,
    pub bytes_sent: Counter,
}

impl UdcnMetrics {
    /// Creates a new metrics instance.
    pub fn new() -> Self {
        Self {
            // Initialize all metrics
            interests_received: Counter::new(),
            interests_satisfied: Counter::new(),
            interests_timed_out: Counter::new(),
            interests_forwarded: Counter::new(),
            data_received: Counter::new(),
            data_sent: Counter::new(),
            
            cs_hits: Counter::new(),
            cs_misses: Counter::new(),
            cs_inserts: Counter::new(),
            cs_evictions: Counter::new(),
            cs_size: Gauge::new(),
            
            pit_inserts: Counter::new(),
            pit_hits: Counter::new(),
            pit_misses: Counter::new(),
            pit_expirations: Counter::new(),
            pit_size: Gauge::new(),
            
            fib_hits: Counter::new(),
            fib_misses: Counter::new(),
            fib_size: Gauge::new(),
            
            interest_processing_time: Timer::new(),
            data_processing_time: Timer::new(),
            
            bytes_received: Counter::new(),
            bytes_sent: Counter::new(),
        }
    }
}
