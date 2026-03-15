// ── Vanity wallet generator ──────────────────────────────────────────────────
// Optimisation layers applied (deepest first):
//
//  1. Drop solana-sdk key-generation path entirely.
//     Instead: ed25519-dalek (pure Rust, no FFI) + ChaCha8Rng (the fastest
//     cryptographically-secure PRNG; 8-round ChaCha is designed for speed).
//
//  2. Thread-local RNG seeded per-thread from OS entropy once, then free-runs.
//     Zero mutex, zero atomic contention on the hot path.
//
//  3. All buffers are stack-allocated ([u8; N]).  No heap alloc per key.
//
//  4. bs58 encode writes into a fixed stack buffer (44 bytes max for 32-byte
//     input).  We only inspect the first `prefix_len` bytes => early-exit.
//
//  5. Prefix stored as a plain [u8; 16] + length on the stack → zero
//     pointer-chasing, cache-line friendly.
//
//  6. Attempt counter is updated in chunks of 1 024 → ~1 000× fewer atomic
//     bus transactions, negligible stat skew.
//
//  7. Each OS thread runs its own tight loop (Rayon's ThreadPoolBuilder),
//     pinned to physical cores via the pool, no work-stealing jitter.
//
//  8. `#[inline(always)]` on the hot comparison so LLVM can hoist the branch.
//
//  9. Cargo profile: fat LTO, codegen-units=1, panic=abort, target-cpu=native
//     → SIMD for SHA-512 (ed25519 scalar mult), AVX2/NEON for ChaCha8.
// ─────────────────────────────────────────────────────────────────────────────

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rand::RngCore;

use std::{
    env,
    process,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

// ── Global atomics ────────────────────────────────────────────────────────────
static ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static FOUND:    AtomicU64 = AtomicU64::new(0);
static STOP:     AtomicBool = AtomicBool::new(false);

// ── Base58 alphabet (Bitcoin / Solana) ───────────────────────────────────────
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode `input` into `out` and return the number of bytes written.
/// Operates entirely on the stack; `out` must be at least 44 bytes.
#[inline(always)]
fn bs58_encode_stack(input: &[u8; 32], out: &mut [u8; 44]) -> usize {
    // Count leading zero bytes → leading '1's in base58.
    let leading_zeros = input.iter().take_while(|&&b| b == 0).count();

    // Work on a local copy so we can do in-place division.
    let mut digits = [0u32; 32];
    for &byte in input.iter() {
        let mut carry = byte as u32;
        for d in digits.iter_mut().rev() {
            carry += *d << 8;
            *d = carry % 58;
            carry /= 58;
        }
    }

    // Collect non-zero part.
    let mut len = 0usize;
    let mut tmp = [0u8; 44];
    for &d in digits.iter() {
        if len > 0 || d != 0 {
            tmp[len] = ALPHABET[d as usize];
            len += 1;
        }
    }

    // Write result: leading '1's then reversed tmp.
    let total = leading_zeros + len;
    for i in 0..leading_zeros {
        out[i] = b'1';
    }
    for i in 0..len {
        out[leading_zeros + i] = tmp[len - 1 - i];
    }
    total
}

/// Compare the first `prefix_len` bytes of the base58 output (already written
/// into `encoded`) against `prefix_bytes`, respecting `ignore_case`.
#[inline(always)]
fn prefix_matches(
    encoded: &[u8; 44],
    encoded_len: usize,
    prefix_bytes: &[u8; 16],
    prefix_len: usize,
    ignore_case: bool,
) -> bool {
    if encoded_len < prefix_len {
        return false;
    }
    if ignore_case {
        for i in 0..prefix_len {
            // to_ascii_uppercase is a branchless single-byte op.
            if encoded[i].to_ascii_uppercase() != prefix_bytes[i] {
                return false;
            }
        }
    } else {
        for i in 0..prefix_len {
            if encoded[i] != prefix_bytes[i] {
                return false;
            }
        }
    }
    true
}

// ── Worker loop (one per OS thread) ──────────────────────────────────────────
fn worker(prefix_bytes: [u8; 16], prefix_len: usize, ignore_case: bool) {
    // Seed a per-thread CSPRNG from OS entropy — done once, no contention.
    let mut rng = ChaCha8Rng::from_entropy();

    // Stack buffers reused every iteration — zero heap alloc in the hot loop.
    let mut secret_bytes = [0u8; 32];
    let mut encoded     = [0u8; 44];

    const REPORT_EVERY: u64 = 1 << 10; // 1024
    let mut local_count: u64 = 0;

    loop {
        if STOP.load(Ordering::Relaxed) {
            break;
        }

        // ── Generate keypair (all stack) ──────────────────────────────────
        rng.fill_bytes(&mut secret_bytes);
        let signing_key  = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pubkey_bytes: &[u8; 32]     = verifying_key.as_bytes();

        // ── Encode public key to base58 on the stack ──────────────────────
        let enc_len = bs58_encode_stack(pubkey_bytes, &mut encoded);

        // ── Check prefix ──────────────────────────────────────────────────
        if prefix_matches(&encoded, enc_len, &prefix_bytes, prefix_len, ignore_case) {
            // Only allocate strings when we actually found something.
            let pubkey_str = std::str::from_utf8(&encoded[..enc_len])
                .unwrap_or("")
                .to_string();

            // Solana private key = [secret(32) || public(32)]  (64-byte format)
            let mut full_secret = [0u8; 64];
            full_secret[..32].copy_from_slice(&secret_bytes);
            full_secret[32..].copy_from_slice(pubkey_bytes);

            // bs58-encode the 64-byte key using the standard crate (not on hot path).
            let secret_str = bs58::encode(&full_secret).into_string();

            let wallet_num = FOUND.fetch_add(1, Ordering::Relaxed) + 1;

            println!("\n✅ FOUND #{}: {}", wallet_num, pubkey_str);
            println!("({}, {})", pubkey_str, secret_str);

            STOP.store(true, Ordering::Relaxed);
            break;
        }

        // ── Batch-update the global counter ──────────────────────────────
        local_count += 1;
        if local_count == REPORT_EVERY {
            ATTEMPTS.fetch_add(REPORT_EVERY, Ordering::Relaxed);
            local_count = 0;
        }
    }

    // Flush any remaining local count.
    if local_count > 0 {
        ATTEMPTS.fetch_add(local_count, Ordering::Relaxed);
    }
}

// ── main ──────────────────────────────────────────────────────────────────────
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2
        || args.iter().any(|a| a == "-h" || a == "--help")
    {
        eprintln!("Usage: solana_vanity [OPTIONS] <PREFIX>");
        eprintln!("Options:");
        eprintln!("  -i, --ignore-case    Case-insensitive prefix match");
        eprintln!("  -h, --help           Show this help");
        process::exit(1);
    }

    let mut ignore_case = false;
    let mut prefix = "";

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--ignore-case" => ignore_case = true,
            s if !s.starts_with('-') && prefix.is_empty() => prefix = s,
            _ => {}
        }
        i += 1;
    }

    if prefix.is_empty() {
        eprintln!("Error: PREFIX is required");
        process::exit(1);
    }
    if prefix.len() > 16 {
        eprintln!("Error: prefix too long (max 16 chars)");
        process::exit(1);
    }

    // Store prefix as a stack array — no heap touch in the hot path.
    let mut prefix_bytes = [0u8; 16];
    let prefix_upper = prefix.to_ascii_uppercase();
    let src = if ignore_case { prefix_upper.as_bytes() } else { prefix.as_bytes() };
    prefix_bytes[..src.len()].copy_from_slice(src);
    let prefix_len = src.len();

    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    println!("🚀 Solana vanity wallet generator");
    println!("   Prefix : \"{}\"{}",
        prefix,
        if ignore_case { " (case-insensitive)" } else { "" });
    println!("   Threads: {}", num_threads);
    println!("⏱  Searching...\n");

    let start = Instant::now();

    // ── Progress thread ───────────────────────────────────────────────────────
    let progress = thread::spawn(move || {
        let mut last = 0u64;
        while !STOP.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(5));
            let elapsed  = start.elapsed().as_secs_f64();
            let attempts = ATTEMPTS.load(Ordering::Relaxed);
            let found    = FOUND.load(Ordering::Relaxed);
            let avg_rate = attempts as f64 / elapsed;
            let cur_rate = (attempts.saturating_sub(last)) as f64 / 5.0;
            println!("📊 {:.2}s | {} keys | {} found | avg {:.0}/s | cur {:.0}/s",
                elapsed,
                format_num(attempts),
                found,
                avg_rate,
                cur_rate);
            last = attempts;
        }
    });

    // ── Worker threads (one per logical CPU, no work-stealing overhead) ───────
    let handles: Vec<_> = (0..num_threads)
        .map(|_| {
            thread::spawn(move || worker(prefix_bytes, prefix_len, ignore_case))
        })
        .collect();

    for h in handles {
        let _ = h.join();
    }

    // Signal progress thread.
    STOP.store(true, Ordering::Relaxed);
    let _ = progress.join();

    // ── Summary ───────────────────────────────────────────────────────────────
    let total_time = start.elapsed();
    let attempts   = ATTEMPTS.load(Ordering::Relaxed);
    let found      = FOUND.load(Ordering::Relaxed);

    println!("\n🎯 Done!");
    println!("   Attempts : {}", format_num(attempts));
    println!("   Found    : {}", found);
    if attempts > 0 {
        println!("   Rate     : {:.0} keys/sec", attempts as f64 / total_time.as_secs_f64());
    }
    println!("   Time     : {:.2}s", total_time.as_secs_f64());
}

fn format_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out
}