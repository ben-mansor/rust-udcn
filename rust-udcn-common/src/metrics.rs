//! Metrics collection and reporting for μDCN.
//!
//! This module provides utilities for tracking and reporting performance metrics
//! across both userspace and kernel components.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/* ---------------------------------------------------------------- *
 * Simple Counter
 * ---------------------------------------------------------------- */

#[derive(Debug)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, value: u64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }

    pub fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Counter {
    fn clone(&self) -> Self {
        let c = Counter::new();
        c.value.store(self.value.load(Ordering::Relaxed), Ordering::Relaxed);
        c
    }
}

/* ---------------------------------------------------------------- *
 * Gauge
 * ---------------------------------------------------------------- */

#[derive(Debug)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Histogram {
    fn clone(&self) -> Self {
        Self {
            buckets: self
                .buckets
                .iter()
                .map(|b| AtomicU64::new(b.load(Ordering::Relaxed)))
                .collect(),
            boundaries: self.boundaries.clone(),
            underflow: AtomicU64::new(self.underflow.load(Ordering::Relaxed)),
            overflow: AtomicU64::new(self.overflow.load(Ordering::Relaxed)),
            sum: AtomicU64::new(self.sum.load(Ordering::Relaxed)),
            count: AtomicU64::new(self.count.load(Ordering::Relaxed)),
        }
    }
}

impl Clone for Gauge {
    fn clone(&self) -> Self {
        let g = Gauge::new();
        g.value.store(self.value.load(Ordering::Relaxed), Ordering::Relaxed);
        g
    }
}

/* ---------------------------------------------------------------- *
 * Histogram
 * ---------------------------------------------------------------- */

#[derive(Debug)]
pub struct Histogram {
    buckets: Vec<AtomicU64>,
    boundaries: Vec<u64>,
    underflow: AtomicU64,
    overflow: AtomicU64,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    pub fn new(boundaries: Vec<u64>) -> Self {
        let buckets = (0..boundaries.len())
            .map(|_| AtomicU64::new(0))
            .collect();

        Self {
            buckets,
            boundaries,
            underflow: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn exponential(min: u64, max: u64, buckets: usize) -> Self {
        assert!(min < max && buckets > 1);
        let factor = (max as f64 / min as f64).powf(1.0 / (buckets as f64 - 1.0));
        let mut boundaries = Vec::with_capacity(buckets);
        let mut value = min;
        for _ in 0..buckets {
            boundaries.push(value);
            value = (value as f64 * factor).ceil() as u64;
        }
        Self::new(boundaries)
    }

    pub fn observe(&self, value: u64) {
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        if value < self.boundaries[0] {
            self.underflow.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let mut idx = self.boundaries.len();
        for (i, &b) in self.boundaries.iter().enumerate() {
            if value <= b {
                idx = i;
                break;
            }
        }

        if idx < self.buckets.len() {
            self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        } else {
            self.overflow.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn average(&self) -> f64 {
        let c = self.count.load(Ordering::Relaxed);
        if c == 0 {
            0.0
        } else {
            self.sum.load(Ordering::Relaxed) as f64 / c as f64
        }
    }

    pub fn counts(&self) -> Vec<(u64, u64)> {
        self.boundaries
            .iter()
            .zip(self.buckets.iter())
            .map(|(&b, bucket)| (b, bucket.load(Ordering::Relaxed)))
            .collect()
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }
}

/* ---------------------------------------------------------------- *
 * Timer
 * ---------------------------------------------------------------- */

#[derive(Debug)]
pub struct Timer {
    start: Option<Instant>,
    histogram: Histogram,
}

impl Timer {
    pub fn new() -> Self {
        let boundaries = vec![10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000];
        Self {
            start: None,
            histogram: Histogram::new(boundaries),
        }
    }

    pub fn with_buckets(boundaries: Vec<u64>) -> Self {
        Self {
            start: None,
            histogram: Histogram::new(boundaries),
        }
    }

    pub fn start(&mut self) {
        self.start = Some(Instant::now());
    }

    pub fn stop(&mut self) -> Duration {
        if let Some(s) = self.start.take() {
            let elapsed = s.elapsed();
            self.histogram.observe(elapsed.as_micros() as u64);
            elapsed
        } else {
            Duration::from_secs(0)
        }
    }

    pub fn histogram(&self) -> &Histogram {
        &self.histogram
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Timer {
    fn clone(&self) -> Self {
        Self {
            start: None,
            histogram: self.histogram.clone(),
        }
    }
}

/* ---------------------------------------------------------------- *
 * Aggregate metrics for µDCN
 * ---------------------------------------------------------------- */

#[derive(Debug, Default, Clone)]
pub struct UdcnMetrics {
    // Packet processing metrics
    pub interests_received: Counter,
    pub interests_satisfied: Counter,
    pub interests_timed_out: Counter,
    /// Number of Interests sent out
    pub interests_sent: Counter,
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
    pub fn new() -> Self {
        Self::default()
    }
}
