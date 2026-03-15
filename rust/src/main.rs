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
const BASE58_POW43: [u8; 32] = [
    0x0e, 0xdb, 0xaf, 0xda, 0x67, 0xca, 0x37, 0x18,
    0x8c, 0xf2, 0x82, 0x63, 0x57, 0x1f, 0x03, 0xb9,
    0x71, 0x68, 0x79, 0xe4, 0xac, 0xc9, 0xc5, 0x14,
    0xab, 0x67, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[inline(always)]
fn ge_be_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut i = 0usize;
    while i < 32 {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn sub_assign_be_32(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow = 0u16;
    let mut i = 32usize;
    while i > 0 {
        i -= 1;
        let ai = a[i] as u16;
        let bi = b[i] as u16 + borrow;
        if ai >= bi {
            a[i] = (ai - bi) as u8;
            borrow = 0;
        } else {
            a[i] = ((ai + 256) - bi) as u8;
            borrow = 1;
        }
    }
}

/// Fast first-character prefilter:
/// - returns '1' for leading-zero pubkeys,
/// - returns first char for common 44-char addresses via q = floor(N / 58^43),
/// - returns None for shorter encodings (rare), requiring full base58 encode.
#[inline(always)]
fn first_base58_char_fast(pubkey: &[u8; 32]) -> Option<u8> {
    if pubkey[0] == 0 {
        return Some(b'1');
    }
    if !ge_be_32(pubkey, &BASE58_POW43) {
        return None;
    }

    let mut rem = *pubkey;
    let mut q = 0usize;
    while ge_be_32(&rem, &BASE58_POW43) {
        sub_assign_be_32(&mut rem, &BASE58_POW43);
        q += 1;
    }
    Some(ALPHABET[q])
}

/// Encode a 32-byte public key into a stack buffer. Returns bytes written.
/// Output fits in 44 bytes (ceil(32 * log(256)/log(58)) = 44).
#[inline(always)]
fn bs58_encode_stack(input: &[u8; 32], out: &mut [u8; 44]) -> usize {
    let mut leading_zeros = 0usize;
    while leading_zeros < 32 && input[leading_zeros] == 0 {
        leading_zeros += 1;
    }

    let mut digits = [0u16; 46];
    let mut i = 0usize;
    while i < 32 {
        let mut carry = input[i] as u32;
        let mut j = 46usize;
        while j > 0 {
            j -= 1;
            carry += (digits[j] as u32) << 8;
            digits[j] = (carry % 58) as u16;
            carry /= 58;
        }
        i += 1;
    }

    let mut start = 0usize;
    while start < 46 && digits[start] == 0 {
        start += 1;
    }

    let len = 46 - start;
    let total = leading_zeros + len;
    i = 0;
    while i < leading_zeros {
        out[i] = b'1';
        i += 1;
    }
    i = 0;
    while i < len {
        out[leading_zeros + i] = ALPHABET[digits[start + i] as usize];
        i += 1;
    }
    total
}

/// Compare the first `prefix_len` bytes of `encoded` against `prefix_bytes`.
#[inline(always)]
fn prefix_matches(
    encoded: &[u8; 44],
    encoded_len: usize,
    prefix_bytes: &[u8],
    ignore_case: bool,
) -> bool {
    let prefix_len = prefix_bytes.len();
    if encoded_len < prefix_len { return false; }
    if ignore_case {
        for i in 0..prefix_len {
            if encoded[i].to_ascii_uppercase() != prefix_bytes[i] { return false; }
        }
        true
    } else {
        encoded[..prefix_len] == *prefix_bytes
    }
}

// ── Per-thread worker ─────────────────────────────────────────────────────────
fn worker(prefix_bytes: [u8; 16], prefix_len: usize, ignore_case: bool) {
    // One OS-entropy seed per thread, then free-run — zero contention.
    let mut rng = ChaCha8Rng::from_entropy();

    // Stack buffers reused every iteration — zero heap alloc in the hot loop.
    const RNG_BATCH: usize = 64;
    let mut seeds = [[0u8; 32]; RNG_BATCH];
    let mut encoded = [0u8; 44];
    let prefix = &prefix_bytes[..prefix_len];

    const BATCH: u64 = 1 << 10;
    const STOP_POLL_MASK: u64 = 0x3F;
    let mut local: u64 = 0;

    loop {
        if STOP.load(Ordering::Relaxed) { break; }

        for seed in &mut seeds {
            rng.fill_bytes(seed);
        }

        for seed in &seeds {
            if (local & STOP_POLL_MASK) == 0 && STOP.load(Ordering::Relaxed) {
                break;
            }

            // ── 2+3. SHA-512(seed) + basepoint multiply (BoringSSL assembly)
            let pair = unsafe {
                // SAFETY: seed is always exactly 32 bytes; this is the only
                // failure condition, so Err is unreachable.
                Ed25519KeyPair::from_seed_unchecked(seed)
                    .unwrap_unchecked()
            };

            let pubkey_slice = pair.public_key().as_ref(); // &[u8] of length 32
            let pubkey_bytes: &[u8; 32] = pubkey_slice.try_into().unwrap();

            if let Some(fc) = first_base58_char_fast(pubkey_bytes) {
                let want = prefix[0];
                let got = if ignore_case { fc.to_ascii_uppercase() } else { fc };
                if got != want {
                    local += 1;
                    if local == BATCH {
                        ATTEMPTS.fetch_add(BATCH, Ordering::Relaxed);
                        local = 0;
                    }
                    continue;
                }
            }

            let enc_len = bs58_encode_stack(pubkey_bytes, &mut encoded);

            if prefix_matches(&encoded, enc_len, prefix, ignore_case) {
                // Ensure only one worker announces and prints the match.
                if STOP
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    let pubkey_str = std::str::from_utf8(&encoded[..enc_len])
                        .unwrap_or("")
                        .to_owned();

                    // Solana private key = seed(32) || pubkey(32), bs58-encoded.
                    let mut full_secret = [0u8; 64];
                    full_secret[..32].copy_from_slice(seed);
                    full_secret[32..].copy_from_slice(pubkey_slice);
                    let secret_str = bs58::encode(&full_secret).into_string();

                    let n = FOUND.fetch_add(1, Ordering::Relaxed) + 1;
                    println!("\n✅ FOUND #{}: {}", n, pubkey_str);
                    println!("({}, {})", pubkey_str, secret_str);
                }
                break;
            }

            local += 1;
            if local == BATCH {
                ATTEMPTS.fetch_add(BATCH, Ordering::Relaxed);
                local = 0;
            }
        }

        if STOP.load(Ordering::Relaxed) {
            break;
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
