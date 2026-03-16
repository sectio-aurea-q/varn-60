// VÄRN-60 (Anu) — Module: Cross-Process Timing
//
// Real attacks happen across process boundaries or over a network.
// This module tests if timing leaks survive:
//   - Inter-process communication (localhost TCP)
//   - Added noise from context switches and network stack
//
// Architecture:
//   Server: listens on TCP, receives ciphertexts, decapsulates, responds
//   Client: sends crafted ciphertexts, measures response time

use crate::target::{MlKemTarget, SecurityLevel};
use crate::analysis::Statistics;
use serde::Serialize;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

const PORT: u16 = 31337;
const MAGIC_VALID: u8 = 0x01;
const MAGIC_INVALID: u8 = 0x02;
const MAGIC_DONE: u8 = 0xFF;

#[derive(Debug, Serialize)]
pub struct CrossProcessResult {
    pub level: String,
    pub valid_mean_ns: f64,
    pub invalid_mean_ns: f64,
    pub delta_ns: f64,
    pub cohens_d: f64,
    pub samples: usize,
    pub verdict: String,
}

pub fn run_cross_process_server(level: SecurityLevel) {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Cross-Process Timing Server        ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Level: {}", level);
    println!("  Listening on 127.0.0.1:{}", PORT);
    println!("  Run 'anu cross-client' in another terminal to start test.");
    println!();

    let target = MlKemTarget::new(level);
    let (valid_ct, _) = target.encapsulate();
    let ct_len = valid_ct.len();

    let listener = TcpListener::bind(format!("127.0.0.1:{}", PORT))
        .expect("Failed to bind");

    println!("  Waiting for connection...");

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            println!("  Client connected.");

            // Send ciphertext length first
            stream.write_all(&(ct_len as u32).to_le_bytes()).ok();

            // Send valid ciphertext
            stream.write_all(&valid_ct).ok();

            // Process requests
            let mut cmd = [0u8; 1];
            let mut ct_buf = vec![0u8; ct_len];

            loop {
                if stream.read_exact(&mut cmd).is_err() { break; }

                match cmd[0] {
                    MAGIC_VALID => {
                        let (_, _elapsed) = target.timed_decapsulate(&valid_ct);
                        stream.write_all(&[0x01]).ok(); // ACK
                    }
                    MAGIC_INVALID => {
                        if stream.read_exact(&mut ct_buf).is_err() { break; }
                        let (_, _elapsed) = target.timed_decapsulate(&ct_buf);
                        stream.write_all(&[0x01]).ok(); // ACK
                    }
                    MAGIC_DONE => {
                        println!("  Client finished. Shutting down.");
                        break;
                    }
                    _ => { break; }
                }
            }
            break; // One client session
        }
    }
}

pub fn run_cross_process_client(samples: usize) -> CrossProcessResult {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║     VÄRN-60 (Anu) — Cross-Process Timing Client        ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Connecting to 127.0.0.1:{}...", PORT);

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", PORT))
        .expect("Failed to connect — is the server running?");

    // Read ciphertext length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).expect("read len");
    let ct_len = u32::from_le_bytes(len_buf) as usize;

    // Read valid ciphertext
    let mut valid_ct = vec![0u8; ct_len];
    stream.read_exact(&mut valid_ct).expect("read ct");

    // Generate invalid ciphertext
    let mut invalid_ct = vec![0u8; ct_len];
    for b in invalid_ct.iter_mut() { *b = rand::random(); }

    println!("  CT length: {} bytes", ct_len);
    println!("  Measuring {} samples (interleaved)...", samples);

    let mut valid_times: Vec<u64> = Vec::with_capacity(samples);
    let mut invalid_times: Vec<u64> = Vec::with_capacity(samples);
    let mut ack = [0u8; 1];

    // Warmup
    for _ in 0..100 {
        stream.write_all(&[MAGIC_VALID]).ok();
        stream.read_exact(&mut ack).ok();
    }

    // Interleaved measurement
    for _i in 0..samples {
        // Valid
        let start = Instant::now();
        stream.write_all(&[MAGIC_VALID]).ok();
        stream.read_exact(&mut ack).ok();
        valid_times.push(start.elapsed().as_nanos() as u64);

        // Invalid
        let start = Instant::now();
        stream.write_all(&[MAGIC_INVALID]).ok();
        stream.write_all(&invalid_ct).ok();
        stream.read_exact(&mut ack).ok();
        invalid_times.push(start.elapsed().as_nanos() as u64);

        if i > 0 && i % 5000 == 0 {
            println!("    {} / {} samples...", i, samples);
        }
    }

    // Done
    stream.write_all(&[MAGIC_DONE]).ok();

    let vs = Statistics::from_samples(&valid_times);
    let is = Statistics::from_samples(&invalid_times);
    let delta = vs.mean - is.mean;
    let pooled = ((vs.variance + is.variance) / 2.0).sqrt();
    let d = if pooled > 0.0 { delta.abs() / pooled } else { 0.0 };

    let verdict = if d > 0.2 {
        "LEAK SURVIVES cross-process — exploitable in real-world scenario"
    } else if d > 0.05 {
        "Marginal signal across process boundary — may be amplifiable"
    } else {
        "Timing leak NOT visible across process boundary"
    };

    println!();
    println!("  Results:");
    println!("    Valid (RTT):   {:.0} ± {:.0} ns", vs.mean, vs.stddev);
    println!("    Invalid (RTT): {:.0} ± {:.0} ns", is.mean, is.stddev);
    println!("    Δ = {:.1} ns, Cohen's d = {:.4}", delta, d);
    println!();
    println!("  ════════════════════════════════════════════════════════");
    println!("  VERDICT: {}", verdict);
    println!("  ════════════════════════════════════════════════════════");
    println!();

    CrossProcessResult {
        level: format!("cross-process"),
        valid_mean_ns: vs.mean,
        invalid_mean_ns: is.mean,
        delta_ns: delta,
        cohens_d: d,
        samples,
        verdict: verdict.into(),
    }
}
