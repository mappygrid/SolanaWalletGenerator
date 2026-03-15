# Solana Vanity Wallet Generator

A high-performance Solana vanity address generator that creates wallets with custom prefixes. Includes both a **highly optimized Rust implementation** (~1M keys/sec) and a **simple JavaScript/Node.js version** for easy use.

## 🚀 Features

- **Dual Implementations**: Choose between blazing-fast Rust or easy-to-run JavaScript
- **Case-Sensitive Matching**: Find addresses with exact prefix matches
- **Case-Insensitive Mode**: Use `-i` flag for case-insensitive search
- **Offline Generation**: Keys never leave your machine, no network connection required
- **Multi-threaded**: Rust version uses all CPU cores for maximum performance
- **Progress Tracking**: Real-time stats showing attempts, success rate, and throughput

## 📁 Project Structure

```
.
├── js/                          # JavaScript implementation
│   ├── solana_wallet_gen_prefix.js   # Main generator script
│   └── package.json             # Dependencies (@solana/web3.js)
│
└── rust/                        # Rust implementation (high-performance)
    ├── src/main.rs              # Optimized generator using ring/BoringSSL
    ├── Cargo.toml               # Dependencies & build config
    ├── README.md                # Detailed Rust optimization notes
    └── .cargo/config.toml       # Native CPU target optimizations
```

## 🦀 Rust Version (Recommended for Speed)

### Prerequisites
- Rust 1.75+ ([Install](https://rustup.rs/))
- macOS / Linux (aarch64 or x86-64)

### Usage

```bash
cd rust

# Build (release mode required for full speed)
cargo build --release

# Find a wallet starting with a prefix (case-sensitive)
./target/release/solana_vanity PUMP

# Case-insensitive match
./target/release/solana_vanity -i pump

# Help
./target/release/solana_vanity --help
```

**Example Output:**
```
🚀 Solana vanity wallet generator
   Prefix : "PUMP"
   Threads: 12
⏱  Searching...

✅ FOUND #1: PUMPaBcXyZ...
(PUMPaBcXyZ..., <base58-private-key>)
```

### Performance

| Prefix Length | Expected Attempts | Time at 1M keys/s |
|:-------------:|------------------:|------------------:|
| 2 chars       | ~3,000            | < 1s              |
| 4 chars       | ~11 million       | ~11s              |
| 6 chars       | ~38 billion       | ~10 hrs           |
| 8 chars       | ~128 trillion     | ~4 years          |

**~1,000,000 keys/sec** on Apple M4 Pro (12 threads)

### Optimizations

The Rust version includes extensive performance optimizations:

- **BoringSSL Assembly**: Uses `ring` crate with hand-written ARM assembly for SHA-512 (hardware acceleration) and NEON SIMD for Ed25519
- **Zero Allocations**: All operations use stack-allocated buffers in the hot loop
- **Custom Base58 Encoder**: Stack-based encoding, no heap allocation
- **Thread-local RNG**: ChaCha8Rng per thread, seeded once from OS entropy
- **Fat LTO**: Whole-program inlining with `codegen-units=1`

See [`rust/README.md`](rust/README.md) for detailed optimization notes.

---

## 📦 JavaScript Version (Easy Setup)

### Prerequisites
- Node.js 16+ ([Install](https://nodejs.org/))

### Setup

```bash
cd js
npm install
```

### Usage

```bash
# Find wallets starting with "PUMP" (unlimited)
node solana_wallet_gen_prefix.js PUMP

# Find exactly 5 wallets
node solana_wallet_gen_prefix.js PUMP 5
```

**Example Output:**
```
🚀 Starting Solana vanity wallet generator
📋 Search parameters:
   - Prefix: "PUMP"
   - Max wallets: unlimited
   - Output file: wallets_PUMP_2024-01-15T10-30-00-000Z.txt
⏱️  Starting search...

✅ FOUND #1: PUMPxyz...
🔑 SECRET (base58): xxx...
📈 Found after 1,234,567 attempts

💾 Wallet saved to wallets_PUMP_2024-01-15T10-30-00-000Z.txt
```

The JavaScript version automatically saves found wallets to a timestamped file.

---

## 🔐 Security Notes

- **Offline Generation**: No network connections are made during key generation
- **CSPRNG**: Uses cryptographically secure random number generators (ChaCha8Rng in Rust, OS RNG in JS)
- **Memory Safety**: Rust version uses `zeroize`-compatible memory handling via `ring`
- **No Disk Writing**: Private keys are only printed to stdout (never written to disk by the tool)
- **You Control the Keys**: Back up your private key immediately — vanity addresses are not recoverable!

## 🔧 How It Works

Ed25519 keypair generation for Solana:

```
random seed (32 bytes)
    │
    ▼  SHA-512
expanded key (64 bytes)
    │  clamp first 32 bytes (RFC 8032 §5.1.5)
    ▼  scalar × ED25519_BASEPOINT
public key (32 bytes)
    │
    ▼  base58 encode
Solana address (32–44 chars)
```

Each thread generates seeds, runs this pipeline, and compares against your target prefix.

## 📝 Output Format

Both versions output:
```
(PUBLIC_KEY, PRIVATE_KEY)
```

- **Public Key**: Base58-encoded Solana address (e.g., `PUMPaBcXyZ...`)
- **Private Key**: Base58-encoded 64-byte secret (seed + public key)

Import the private key into Phantom, Solflare, or any Solana wallet supporting raw base58 secret keys.

## 📄 License

MIT — Use at your own risk. Always verify generated keys in a test environment before using with real funds.

## ⚠️ Disclaimer

This tool is for educational and development purposes. The longer your prefix, the exponentially longer the search takes. Be realistic with expectations for 6+ character prefixes.
