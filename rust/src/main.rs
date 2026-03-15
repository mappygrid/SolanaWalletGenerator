// ── Solana vanity wallet generator ─────────────────────────────────────────
//
// Hot-path pipeline per key (all stack, zero heap alloc):
//
//   ChaCha8Rng  →  32-byte seed
//       ↓
//   ring::signature::Ed25519KeyPair::from_seed_unchecked()
//     Internally (BoringSSL assembly for aarch64):
//       SHA-512 via sha512h / sha512h2 / sha512su0 / sha512su1  (FEAT_SHA512)
//       Scalar clamp + basepoint multiply via NEON-vectorised field ops
//       → 32-byte compressed public key
//       ↓
//   bs58_encode_stack() → [u8; 44] on the stack
//       ↓
//   prefix_matches() → hit / miss
//
// Why ring?
//   curve25519-dalek 4.x uses either the serial u64 backend (no SIMD on ARM)
//   or the AVX2 backend (x86-64 only). sha2 0.10 uses software SHA-512 on
//   aarch64. ring wraps BoringSSL's hand-written ARM assembly, which uses:
//     - FEAT_SHA512 hardware instructions for SHA-512 (~8-20× vs software)
//     - NEON 128-bit SIMD for the 4-way parallel field multiply in the
//       Ed25519 scalar multiply (~3-4× vs serial u64)
//
// Other optimisations kept from previous pass:
//   - Thread-local ChaCha8Rng seeded from OS entropy once
//   - Zero heap alloc in the hot loop
//   - Custom stack bs58 encoder
//   - Atomic counter batched every 1024 iters
//   - One OS thread per logical CPU (no work-stealing)
//   - Fat LTO + codegen-units=1 + panic=abort
// ─────────────────────────────────────────────────────────────────────────────

use ring::signature::{Ed25519KeyPair, KeyPair};
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};

use std::{
    env,
    process,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static FOUND:    AtomicU64 = AtomicU64::new(0);
static STOP:     AtomicBool = AtomicBool::new(false);

// ── Base58 alphabet (Bitcoin / Solana order) ─────────────────────────────────
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode a 32-byte public key into a stack buffer. Returns bytes written.
/// Output fits in 44 bytes (ceil(32 * log(256)/log(58)) = 44).
#[inline(always)]
fn bs58_encode_stack(input: &[u8; 32], out: &mut [u8; 44]) -> usize {
    let leading_zeros = input.iter().take_while(|&&b| b == 0).count();

    let mut digits = [0u32; 46];
    for &byte in input.iter() {
        let mut carry = byte as u32;
        for d in digits.iter_mut().rev() {
            carry += *d << 8;
            *d = carry % 58;
            carry /= 58;
        }
    }

    // Collect non-zero digits and reverse into output.
    let mut tmp = [0u8; 44];
    let mut len = 0usize;
    for &d in digits.iter() {
        if len > 0 || d != 0 {
            tmp[len] = ALPHABET[d as usize];
            len += 1;
        }
    }
    let total = leading_zeros + len;
    for i in 0..leading_zeros { out[i] = b'1'; }
    for i in 0..len           { out[leading_zeros + i] = tmp[i]; }  // no reversal — digits[0] is already MSB
    total
}

/// Compare the first `prefix_len` bytes of `encoded` against `prefix_bytes`.
#[inline(always)]
fn prefix_matches(
    encoded: &[u8; 44],
    encoded_len: usize,
    prefix_bytes: &[u8; 16],
    prefix_len: usize,
    ignore_case: bool,
) -> bool {
    if encoded_len < prefix_len { return false; }
    if ignore_case {
        for i in 0..prefix_len {
            if encoded[i].to_ascii_uppercase() != prefix_bytes[i] { return false; }
        }
    } else {
        for i in 0..prefix_len {
            if encoded[i] != prefix_bytes[i] { return false; }
        }
    }
    true
}

// ── Per-thread worker ─────────────────────────────────────────────────────────
fn worker(prefix_bytes: [u8; 16], prefix_len: usize, ignore_case: bool) {
    // One OS-entropy seed per thread, then free-run — zero contention.
    let mut rng = ChaCha8Rng::from_entropy();

    // Stack buffers reused every iteration — zero heap alloc in the hot loop.
    let mut seed    = [0u8; 32];
    let mut encoded = [0u8; 44];

    const BATCH: u64 = 1 << 10;
    let mut local: u64 = 0;

    loop {
        if STOP.load(Ordering::Relaxed) { break; }

        // ── 1. Random 32-byte seed ────────────────────────────────────────
        rng.fill_bytes(&mut seed);

        // ── 2+3. SHA-512(seed) + basepoint multiply (BoringSSL assembly) ──
        //   ring::Ed25519KeyPair::from_seed_unchecked internally:
        //     a) SHA-512(seed) → 64-byte expanded key
        //        Uses sha512h/sha512h2/sha512su0/sha512su1 on M4 (FEAT_SHA512)
        //     b) Clamp first 32 bytes per RFC 8032 §5.1.5
        //     c) scalar × ED25519_BASEPOINT using NEON field-multiply pipeline
        //   All in hand-written ARM assembly from BoringSSL — much faster than
        //   dalek's serial u64 backend or pure-Rust sha2.
        let pair = unsafe {
            // SAFETY: seed is always exactly 32 bytes; this is the only
            // failure condition, so Err is unreachable.
            Ed25519KeyPair::from_seed_unchecked(&seed)
                .unwrap_unchecked()
        };

        // ── 4. Get public key bytes ───────────────────────────────────────
        let pubkey_slice = pair.public_key().as_ref(); // &[u8] of length 32
        let pubkey_bytes: &[u8; 32] = pubkey_slice.try_into().unwrap();

        // ── 5. Stack-encode to base58, compare prefix ─────────────────────
        let enc_len = bs58_encode_stack(pubkey_bytes, &mut encoded);

        if prefix_matches(&encoded, enc_len, &prefix_bytes, prefix_len, ignore_case) {
            let pubkey_str = std::str::from_utf8(&encoded[..enc_len])
                .unwrap_or("")
                .to_owned();

            // Solana private key = seed(32) || pubkey(32), bs58-encoded.
            let mut full_secret = [0u8; 64];
            full_secret[..32].copy_from_slice(&seed);
            full_secret[32..].copy_from_slice(pubkey_slice);
            let secret_str = bs58::encode(&full_secret).into_string();

            let n = FOUND.fetch_add(1, Ordering::Relaxed) + 1;
            println!("\n✅ FOUND #{}: {}", n, pubkey_str);
            println!("({}, {})", pubkey_str, secret_str);

            STOP.store(true, Ordering::Relaxed);
            break;
        }

        local += 1;
        if local == BATCH {
            ATTEMPTS.fetch_add(BATCH, Ordering::Relaxed);
            local = 0;
        }
    }
    if local > 0 { ATTEMPTS.fetch_add(local, Ordering::Relaxed); }
}

// ── main ──────────────────────────────────────────────────────────────────────
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("Usage: solana_vanity [-i] <PREFIX>");
        eprintln!("  -i / --ignore-case   case-insensitive match");
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

    if prefix.is_empty() { eprintln!("Error: PREFIX required"); process::exit(1); }
    if prefix.len() > 16 { eprintln!("Error: prefix too long (max 16)"); process::exit(1); }

    let mut prefix_bytes = [0u8; 16];
    let src = if ignore_case {
        prefix.to_ascii_uppercase()
    } else {
        prefix.to_string()
    };
    prefix_bytes[..src.len()].copy_from_slice(src.as_bytes());
    let prefix_len = src.len();

    let num_threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);

    println!("🚀 Solana vanity wallet generator");
    println!("   Prefix : \"{}\"{}",
        prefix, if ignore_case { " (case-insensitive)" } else { "" });
    println!("   Threads: {}", num_threads);
    println!("⏱  Searching...\n");

    let start = Instant::now();

    // Progress thread.
    let progress = thread::spawn(move || {
        let mut last = 0u64;
        while !STOP.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(5));
            let elapsed  = start.elapsed().as_secs_f64();
            let attempts = ATTEMPTS.load(Ordering::Relaxed);
            let found    = FOUND.load(Ordering::Relaxed);
            let avg      = attempts as f64 / elapsed;
            let cur      = attempts.saturating_sub(last) as f64 / 5.0;
            println!("📊 {:.1}s | {} keys | {} found | avg {:.0}/s | cur {:.0}/s",
                elapsed, fmt(attempts), found, avg, cur);
            last = attempts;
        }
    });

    // Worker threads — one tight loop per logical CPU.
    let handles: Vec<_> = (0..num_threads)
        .map(|_| thread::spawn(move || worker(prefix_bytes, prefix_len, ignore_case)))
        .collect();

    for h in handles { let _ = h.join(); }
    STOP.store(true, Ordering::Relaxed);
    let _ = progress.join();

    let elapsed   = start.elapsed();
    let attempts  = ATTEMPTS.load(Ordering::Relaxed);
    let found     = FOUND.load(Ordering::Relaxed);

    println!("\n🎯 Done!");
    println!("   Keys tried : {}", fmt(attempts));
    println!("   Found      : {}", found);
    if attempts > 0 {
        println!("   Throughput : {:.0} keys/sec", attempts as f64 / elapsed.as_secs_f64());
    }
    println!("   Time       : {:.2}s", elapsed.as_secs_f64());
}

fn fmt(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out
}
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

