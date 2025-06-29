//! Benchmarking command implementation for µDCN CLI

use anyhow::{Context, Result};
use futures::future::join_all;
use log::{debug, info, warn};
use rust_udcn_common::ndn::{Interest, Name};
use rust_udcn_quic::{ClientOptions, NdnQuicTransport, TransportConfig, TransportMode};
use std::{sync::Arc, time::{Duration, Instant}};
use tokio::{sync::Mutex, time::timeout};

/// Run the benchmark with the specified parameters
pub async fn run_benchmark(count: usize, prefix: String, concurrent: usize) -> Result<()> {
    info!(
        "Running benchmark: count={}, prefix={}, concurrent={}",
        count, prefix, concurrent
    );

    println!("Starting µDCN benchmark");
    println!("======================");
    println!("Parameters:");
    println!("  Interest count: {}", count);
    println!("  Name prefix: {}", prefix);
    println!("  Concurrent requests: {}", concurrent);
    println!();

    // Configure the QUIC transport
    let config = TransportConfig {
        mode: TransportMode::Client,
        client_options: ClientOptions {
            verify_certificate: false, // For testing only
            ..Default::default()
        },
        interest_timeout_ms: 4000, // 4 seconds timeout
        ..Default::default()
    };

    // Create the transport
    let transport = Arc::new(NdnQuicTransport::new(config).await
        .context("Failed to create QUIC transport")?);

    // Connect to the NDN router (localhost in this case)
    println!("Connecting to localhost:6367...");
    let face = transport.connect(("localhost", 6367)).await
        .context("Failed to connect to NDN router")?;
    println!("Connected to NDN router.");

    // Prepare for the benchmark
    let start_time = Instant::now();
    let results = Arc::new(Mutex::new(BenchmarkResults {
        total_interests: count,
        successful_requests: 0,
        failed_requests: 0,
        timeouts: 0,
        total_time_ms: 0,
        min_rtt_ms: u64::MAX,
        max_rtt_ms: 0,
        total_rtt_ms: 0,
    }));

    println!("\nRunning benchmark...");

    // Split the interests into batches
    let batch_size = std::cmp::max(1, count / concurrent);
    let mut tasks = Vec::new();

    for batch_index in 0..concurrent {
        let start_index = batch_index * batch_size;
        let end_index = if batch_index == concurrent - 1 {
            count
        } else {
            start_index + batch_size
        };

        if start_index >= count {
            break;
        }

        // Clone references for the task
        let transport_clone = Arc::clone(&transport);
        let face_id = face.id().to_string();
        let prefix_clone = prefix.clone();
        let results_clone = Arc::clone(&results);

        // Create a task to run this batch of interests
        let task = tokio::spawn(async move {
            for i in start_index..end_index {
                // Create a unique name for this interest
                let name_str = format!("{}/{}", prefix_clone, i);
                let name = Name::from_string(&name_str)
                    .expect("failed to parse benchmark name");

                // Create an interest
                let mut interest = Interest::new(name);
                interest.set_can_be_prefix(false);
                interest.set_must_be_fresh(true);

                // Start measuring time
                let request_start = Instant::now();

                // Send the interest and wait for data with a timeout
                let result = timeout(
                    Duration::from_millis(4000), // 4 seconds timeout
                    transport_clone.express_interest(interest, Some(&face_id), None)
                ).await;

                // Calculate RTT
                let rtt_ms = request_start.elapsed().as_millis() as u64;

                // Update results
                let mut results = results_clone.lock().await;
                match result {
                    Ok(Ok(_)) => {
                        results.successful_requests += 1;
                        results.min_rtt_ms = results.min_rtt_ms.min(rtt_ms);
                        results.max_rtt_ms = results.max_rtt_ms.max(rtt_ms);
                        results.total_rtt_ms += rtt_ms;
                    }
                    Ok(Err(_)) => {
                        results.failed_requests += 1;
                    }
                    Err(_) => {
                        results.timeouts += 1;
                    }
                }

                // Update progress if this is the first batch
                if batch_index == 0 && (i - start_index) % 10 == 0 {
                    let progress = (i - start_index + 1) as f64 / (end_index - start_index) as f64;
                    print!("\rProgress: {:.1}%", progress * 100.0);
                    std::io::Write::flush(&mut std::io::stdout()).unwrap();
                }
            }
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete
    join_all(tasks).await;

    // Calculate total time
    let total_time_ms = start_time.elapsed().as_millis() as u64;

    // Update final results
    {
        let mut results = results.lock().await;
        results.total_time_ms = total_time_ms;
    }

    // Print results
    print_benchmark_results(results.lock().await.clone()).await;

    // Close the transport
    transport.close().await?;

    Ok(())
}

/// Benchmark results structure
#[derive(Debug, Clone)]
struct BenchmarkResults {
    /// Total number of interests sent
    total_interests: usize,
    
    /// Successful requests (got Data)
    successful_requests: usize,
    
    /// Failed requests (error)
    failed_requests: usize,
    
    /// Timed out requests
    timeouts: usize,
    
    /// Total time for the benchmark (ms)
    total_time_ms: u64,
    
    /// Minimum RTT (ms)
    min_rtt_ms: u64,
    
    /// Maximum RTT (ms)
    max_rtt_ms: u64,
    
    /// Total RTT (ms) for calculating average
    total_rtt_ms: u64,
}

/// Print the benchmark results
async fn print_benchmark_results(results: BenchmarkResults) {
    println!("\n\nBenchmark Results");
    println!("=================");
    println!("Total Interests Sent: {}", results.total_interests);
    println!("Successful Requests: {} ({:.2}%)", 
        results.successful_requests,
        (results.successful_requests as f64 / results.total_interests as f64) * 100.0
    );
    println!("Failed Requests: {} ({:.2}%)", 
        results.failed_requests,
        (results.failed_requests as f64 / results.total_interests as f64) * 100.0
    );
    println!("Timeouts: {} ({:.2}%)", 
        results.timeouts,
        (results.timeouts as f64 / results.total_interests as f64) * 100.0
    );
    
    println!("\nTiming:");
    println!("Total Time: {:.2} seconds", results.total_time_ms as f64 / 1000.0);
    
    if results.successful_requests > 0 {
        println!("Throughput: {:.2} interests/second", 
            results.total_interests as f64 / (results.total_time_ms as f64 / 1000.0)
        );
        println!("Min RTT: {} ms", results.min_rtt_ms);
        println!("Max RTT: {} ms", results.max_rtt_ms);
        println!("Avg RTT: {:.2} ms", 
            results.total_rtt_ms as f64 / results.successful_requests as f64
        );
    }
}
