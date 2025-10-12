use solana_sdk::{
    signature::{Keypair, Signer},
};
use bs58;
use rayon::prelude::*;
use std::{
    fs::OpenOptions,
    io::Write,
    sync::Arc,
    time::{Duration, Instant},
    env,
    process,
};
use std::thread;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// Atomic counters for thread-safe statistics
static ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static FOUND: AtomicU64 = AtomicU64::new(0);
static SHOULD_STOP: AtomicBool = AtomicBool::new(false);

// Simple and fast case-insensitive compare
fn fast_case_insensitive_compare(pubkey: &str, prefix: &str) -> bool {
    if pubkey.len() < prefix.len() {
        return false;
    }

    // Simple and direct approach - let Rust optimize it
    pubkey[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        eprintln!("Usage: cargo run -- [OPTIONS] <PREFIX> [MAX_WALLETS]");
        eprintln!("Examples:");
        eprintln!("  cargo run -- PUMP 10        # Find 10 wallets starting with 'PUMP'");
        eprintln!("  cargo run -- -i pump 5      # Find 5 wallets starting with 'pump' (case insensitive)");
        eprintln!("  cargo run -- -i SOL         # Find unlimited wallets starting with 'sol' (any case)");
        eprintln!("");
        eprintln!("Options:");
        eprintln!("  -i, --ignore-case    Match prefix case-insensitively");
        eprintln!("  -h, --help          Show this help message");
        process::exit(1);
    }

    // Parse arguments
    let mut ignore_case = false;
    let mut prefix_index = 1;
    let mut max_wallets = 0u64;

    for (i, arg) in args.iter().enumerate() {
        match arg.as_str() {
            "-i" | "--ignore-case" => {
                ignore_case = true;
                if prefix_index == i {
                    prefix_index += 1;
                }
            }
            _ if !arg.starts_with('-') && i > 1 && !args[i-1].starts_with('-') => {
                // This is the max_wallets argument (not a flag and not the first non-flag argument)
                max_wallets = arg.parse::<u64>().unwrap_or(0);
            }
            _ if !arg.starts_with('-') && prefix_index == 1 && i != 1 => {
                // Skip non-prefix arguments
            }
            _ => {}
        }
    }

    // Find the prefix argument (first non-flag argument)
    let mut prefix = "";
    for (i, arg) in args.iter().enumerate() {
        if !arg.starts_with('-') && *arg != args[0] {
            prefix = arg;
            break;
        }
    }

    if prefix.is_empty() {
        eprintln!("Error: PREFIX is required");
        process::exit(1);
    }

    // Convert prefix to uppercase if case insensitive
    let search_prefix = if ignore_case {
        prefix.to_uppercase()
    } else {
        prefix.to_string()
    };

    // Create output file name based on prefix and timestamp
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S%.3fZ");
    let output_file = format!("wallets_{}_{}.txt", prefix, timestamp);
    let output_path = format!("wallets/{}", output_file);

    println!("🚀 Starting Solana vanity wallet generator");
    println!("📋 Search parameters:");
    println!("   - Prefix: \"{}\"{}", prefix, if ignore_case { " (case insensitive)" } else { "" });
    let max_wallets_str = if max_wallets == 0 { "unlimited".to_string() } else { max_wallets.to_string() };
    println!("   - Max wallets: {}", max_wallets_str);
    println!("   - Output file: {}", output_path);
    println!("⏱️  Starting search...\n");

    let start_time = Instant::now();
    let output_path_arc = Arc::new(output_path);
    let prefix_arc = Arc::new(search_prefix.clone());

    // Spawn progress logging thread
    let progress_handle = {
        let start_time_clone = start_time;

        thread::spawn(move || {
            let mut last_attempts = 0u64;
            while !SHOULD_STOP.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(5));

                let elapsed = start_time_clone.elapsed().as_secs_f64();
                let attempts = ATTEMPTS.load(Ordering::Relaxed);
                let found = FOUND.load(Ordering::Relaxed);

                if attempts > 0 {
                    let rate = attempts as f64 / elapsed;
                    let success_rate = (found as f64 / attempts as f64) * 100.0;
                    let batch_rate = if attempts > last_attempts {
                        (attempts - last_attempts) as f64 / 5.0
                    } else {
                        0.0
                    };
                    println!("📊 Progress: {} attempts, {} found ({:.4}% success rate, {:.0} avg/sec, {:.0} current/sec)",
                        format_number(attempts), found, success_rate, rate, batch_rate);
                    last_attempts = attempts;
                }
            }
        })
    };

    // Determine optimal settings
    let num_threads = rayon::current_num_threads();
    let batch_size = 50000; // Optimal batch size
    println!("🔧 Using {} threads with batch size {}", num_threads, batch_size);

    // Start simple and fast parallel wallet generation
    let generation_handle = thread::spawn({
        let prefix_clone = prefix_arc.clone();
        let output_path_clone = output_path_arc.clone();
        let ignore_case_clone = ignore_case;

        move || {
            while !SHOULD_STOP.load(Ordering::Relaxed) {
                let current_found = FOUND.load(Ordering::Relaxed);
                if max_wallets > 0 && current_found >= max_wallets {
                    break;
                }

                // Generate wallets in parallel - simple and fast
                let wallets_found: Vec<_> = (0..batch_size)
                    .into_par_iter()
                    .filter_map(|_| {
                        let keypair = Keypair::new();
                        let pubkey = keypair.pubkey().to_string();

                        let matches = if ignore_case_clone {
                            fast_case_insensitive_compare(&pubkey, &*prefix_clone)
                        } else {
                            pubkey.starts_with(&*prefix_clone)
                        };

                        if matches {
                            let secret_key = bs58::encode(keypair.to_bytes()).into_string();
                            Some((pubkey, secret_key))
                        } else {
                            None
                        }
                    })
                    .collect();

                // Update attempt counter
                ATTEMPTS.fetch_add(batch_size, Ordering::Relaxed);

                // Process found wallets
                for (pubkey, secret_key) in wallets_found {
                    let wallet_num = FOUND.fetch_add(1, Ordering::Relaxed) + 1;

                    println!("\n✅ FOUND #{}: {}", wallet_num, pubkey);
                    println!("🔑 SECRET (base58): {}", secret_key);

                    let attempts = ATTEMPTS.load(Ordering::Relaxed);
                    println!("📈 Found after {} attempts\n", format_number(attempts));

                    // Save to file
                    let wallet_data = format!(
                        "Wallet #{}\n\
                         Public Key:  {}\n\
                         Private Key: {}\n\
                         Found after: {} attempts\n\
                         Timestamp:   {}\n\
                         {}\n\n",
                        wallet_num,
                        pubkey,
                        secret_key,
                        format_number(attempts),
                        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                        "=".repeat(60)
                    );

                    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&*output_path_clone) {
                        if let Err(e) = file.write_all(wallet_data.as_bytes()) {
                            eprintln!("❌ Error writing to file: {}", e);
                        } else {
                            println!("💾 Wallet saved to {}", &*output_path_clone);
                        }
                    } else {
                        eprintln!("❌ Error opening output file");
                    }

                    // Check if we've found enough wallets
                    if max_wallets > 0 && wallet_num >= max_wallets {
                        break;
                    }
                }
            }
        }
    });

    // Wait for generation to complete
    generation_handle.join().unwrap();

    // Signal progress thread to stop and wait for it
    SHOULD_STOP.store(true, Ordering::Relaxed);
    progress_handle.join().unwrap();

    // Final summary
    let total_time = start_time.elapsed();
    let final_attempts = ATTEMPTS.load(Ordering::Relaxed);
    let final_found = FOUND.load(Ordering::Relaxed);

    println!("\n🎯 Search completed!");
    println!("📊 Final statistics:");
    println!("   - Total attempts: {}", format_number(final_attempts));
    println!("   - Wallets found: {}", final_found);

    if final_attempts > 0 {
        let final_success_rate = (final_found as f64 / final_attempts as f64) * 100.0;
        let final_rate = final_attempts as f64 / total_time.as_secs_f64();
        println!("   - Success rate: {:.6}%", final_success_rate);
        println!("   - Average rate: {:.0} attempts/second", final_rate);
    }

    println!("   - Total time: {:.2} seconds", total_time.as_secs_f64());

    if final_found > 0 {
        println!("💾 All wallets saved to: {}", &*output_path_arc);
    }
}

fn format_number(num: u64) -> String {
    let num_str = num.to_string();
    let mut result = String::new();
    let len = num_str.len();

    for (i, ch) in num_str.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }

    result
}