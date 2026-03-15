# Solana Vanity Wallet Generator

Generates Solana keypairs whose public address starts with a chosen prefix.
Runs entirely offline. Keys never leave your machine.

```
$ solana_vanity PUMP
🚀 Solana vanity wallet generator
   Prefix : "PUMP"
   Threads: 12
⏱  Searching...

✅ FOUND #1: PUMPaBcXyZ...
(PUMPaBcXyZ..., <base58-private-key>)
```

---

## Usage

```bash
# Build (release mode required for full speed)
cargo build --release

# Find a wallet starting with a prefix (case-sensitive)
./target/release/solana_vanity PUMP

# Case-insensitive match
./target/release/solana_vanity -i pump

# Help
./target/release/solana_vanity --help
```

**Output format**

```
(PUBLIC_KEY, PRIVATE_KEY)
```

Both keys are base58-encoded. Import the private key directly into Phantom,
Solflare, or any Solana wallet that accepts a raw base58 secret key.

**Difficulty** scales with prefix length — each extra character is ~58× harder:

| Prefix length | Expected attempts | Time at 1 M keys/s |
|:---:|---:|---:|
| 2 | ~3,000 | < 1s |
| 4 | ~11 M | ~11s |
| 6 | ~38 B | ~10 hrs |
| 8 | ~128 T | ~4 years |

---

## How it works

An Ed25519 keypair for Solana is derived as:

```
random seed (32 bytes)
    │
    ▼  SHA-512
expanded key (64 bytes)
    │  clamp first 32 bytes (RFC 8032 §5.1.5)
    ▼  scalar × ED25519_BASEPOINT
public key (32 bytes)
    │
    ▼  base58
Solana address (32–44 chars)
```

Each thread generates seeds, runs this pipeline, and compares the first N
characters of the resulting address against the target prefix.

---

## Performance evolution

The generator started as a straightforward Solana SDK wrapper. Over several
iterations it was profiled and rewritten to squeeze out every available cycle
on Apple Silicon (M-series) and x86-64.

### v1 — Solana SDK + Rayon (~920 k keys/s)

**Bottlenecks identified:**

- `solana-sdk` pulls in ~80 crates (Tokio runtime, RPC clients, BPF
  toolchain). Only `Keypair::new()` was needed — 99% of the dependency
  graph was dead weight that still paid compile-time and link-time costs.
- `Keypair::new()` calls `OsRng` on every single key, meaning a syscall
  (`getrandom`) per key.
- Rayon's work-stealing scheduler added task-dispatch overhead for a
  workload where every unit of work is identical — no need for a
  sophisticated scheduler.
- Keys were heap-allocated (`String`, `Vec`) before the prefix check.
- The attempt counter was incremented atomically on every iteration,
  causing a cache-coherency write to the counter's cache line on every
  CPU core every tick.

### v2 — Drop solana-sdk: ed25519-dalek + ChaCha8Rng + stack buffers

Key changes:

| What | Before | After |
|---|---|---|
| Crypto crate | `solana-sdk` (80 crates) | `ed25519-dalek` (8 crates) |
| Entropy | `OsRng` per key (syscall) | `ChaCha8Rng` seeded once per thread |
| Parallelism | Rayon work-stealing | One plain OS thread per CPU core |
| Heap allocs | `String` + `Vec` per key | Zero — all `[u8; N]` on the stack |
| Atomic writes | Every key | Every 1 024 keys |
| LTO | thin | fat (whole-program) |
| Base58 encoder | `bs58` crate (heap) | Custom stack encoder `[u8; 44]` |
| CPU instructions | default | `target-cpu=native` |

**ChaCha8Rng** is seeded from OS entropy once per thread, then runs freely
at ~4 GB/s with zero syscall overhead per key.

**Batched atomic counter** — updating `AtomicU64` with `Relaxed` ordering
every 1 024 iterations instead of every iteration removes ~1 000 atomic
bus transactions per thread per 1 024 keys. The statistics shown in the
progress line are at most ~1 ms stale — negligible.

**Fat LTO** (`lto = "fat"`) enables whole-program inlining across crate
boundaries. LLVM can inline the ChaCha8 block function, the SHA-512
compression function, and the field arithmetic for the scalar multiply all
into one hot loop, significantly improving instruction scheduling and
eliminating function-call overhead.

### v3 — Switch to `ring` for BoringSSL assembly on aarch64

`curve25519-dalek` 4.x has two backends:
- **Serial u64** — scalar multiplication in portable pure-Rust
- **AVX2 SIMD** — vectorised field arithmetic, but x86-64 only

On Apple M4 (aarch64) the serial backend is always selected. Additionally,
the `sha2` pure-Rust crate does not emit hardware SHA-512 instructions on
ARM even when `FEAT_SHA512` is available.

`ring` wraps Google's **BoringSSL**, which ships hand-written ARM assembly
that:

- Uses `sha512h` / `sha512h2` / `sha512su0` / `sha512su1` ARMv8 crypto
  instructions directly (FEAT\_SHA512), giving hardware-accelerated SHA-512
  that is 8–20× faster than the software implementation.
- Uses **NEON 128-bit SIMD** for the 4-way parallel field multiply in the
  Ed25519 scalar multiplication, roughly 3–4× faster than the serial path.

Result: **~1 000 000 keys/s** on 12 threads (Apple M4 Pro).

### Bug fix — base58 byte-order inversion

The custom `bs58_encode_stack` function built base-58 digits with index 0
as the most-significant digit (big-endian storage in the `digits` array),
but then *reversed* them when writing to the output buffer. This produced
addresses that were a mirror of the correct ones.

The private key was always encoded correctly (using the `bs58` crate), so
importing a key into a wallet always derived a **different** address than
the one displayed — making the tool appear to work while silently producing
unusable output.

Fix: removed the reversal (`tmp[len - 1 - i]` → `tmp[i]`).

---

## Security notes

- Keys are generated entirely offline — no network connection is made.
- Seeds come from the OS CSPRNG (`getrandom`) once per thread; all
  subsequent randomness is derived from ChaCha8Rng, which is
  cryptographically secure.
- Private keys are only printed to stdout; they are never written to disk
  by the tool itself.
- The `ring` crate uses `zeroize`-compatible memory handling for sensitive
  key material.
- **Back up your private key immediately.** Vanity addresses are not
  recoverable from the address alone.

---

## Requirements

- Rust 1.75+
- macOS / Linux (aarch64 or x86-64)
- On Apple Silicon: macOS 11+ (for FEAT\_SHA512 kernel support)

## Building

```bash
cargo build --release
# Binary: target/release/solana_vanity
```

Or use the optimized build helper:

```bash
./scripts/build_optimized.sh
# Optional: PROFILE=dev ./scripts/build_optimized.sh
```

What it enables automatically (when tools are available):

- `sccache` compiler artifact caching (`RUSTC_WRAPPER=sccache`)
- Fast linkers on Linux (`mold`, fallback `lld`)
- Host-aware parallel build jobs (`--jobs <logical-cpus>`)

The `.cargo/config.toml` sets `target-cpu=native` so the binary is
optimised for the machine it was compiled on and is not portable to other
CPU generations.
