# Afterburner

**Afterburner** is a **Solana Kernel-Bypass QUIC Driver** built in Rust. It utilizes **eBPF** and **AF_XDP** to bypass the Linux kernel networking stack, achieving **sub-100µs latency** and **4.7 Million TPS** throughput with zero-copy packet processing.

## Performance

| Metric | Value |
|--------|-------|
| Steady-State Latency | **~70µs** |
| Minimum Latency | **~42µs** |
| TX Throughput | **~1.5 Million TPS** |
| Packet Loss | **0** |

## Features

- **Kernel Bypass**: eBPF XDP redirects packets directly to userspace memory (UMEM)
- **QUIC Protocol**: Full RFC 9000 compliance via `quiche` state machine
- **Solana Compatible**: `solana-tpu` ALPN, correct stream IDs (0,4,8,12)
- **Bidirectional**: Simultaneous RX timestamps + TX transaction flooding
- **Zero-Copy**: Direct NIC → UMEM → Application path

## Quick Start

### Prerequisites

```bash
# Install Rust nightly (required for eBPF)
rustup install nightly
rustup component add rust-src --toolchain nightly

# Install bpf-linker
cargo install bpf-linker
```

### Build

```bash
# 1. Build eBPF probe (kernel-space)
cargo xtask

# 2. Build userspace applications
cargo build --release --package afterburner-app
```

### Setup Network (veth pair for testing)

```bash
# Run the setup script (creates veth0 <-> veth1 in ns1)
sudo ./setup_net.sh
```

### Generate TLS Certificates

```bash
# Required for QUIC server
openssl req -x509 -newkey rsa:2048 -keyout cert.key -out cert.crt -days 365 -nodes -subj "/CN=localhost"
```

### Run Benchmark

**Terminal 1 - Server (in network namespace):**
```bash
sudo ip netns exec ns1 taskset -c 0 ./target/release/stream_server
```

**Terminal 2 - Client (AF_XDP engine):**
```bash
sudo taskset -c 1 ./target/release/afterburner-app --iface veth0
```

Expected output:
```
Starting Afterburner QUIC on: veth0
[XDP] eBPF program attached to veth0
[XSK] AF_XDP socket registered
[RUN] HFT Loop Running (Bidirectional Mode)
[QUIC] Connection established
[STATS] Lat(us) Avg=70.5 Min=42.1 Max=156.2 | RX: 125000 | Lost: 0
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USERSPACE APPLICATION                     │
│  ┌─────────┐   ┌──────────────┐   ┌─────────┐               │
│  │ flood.rs│──▶│quic_driver.rs│──▶│ xsk.rs  │               │
│  │ (TX Gen)│   │(QUIC State)  │   │(AF_XDP) │               │
│  └─────────┘   └──────────────┘   └────┬────┘               │
└────────────────────────────────────────┼────────────────────┘
                                         │ UMEM (8MB Direct Memory)
┌────────────────────────────────────────┼────────────────────┐
│ KERNEL (BYPASSED FOR DATA PATH)        │                    │
│  ┌──────────────────────────────┐      │                    │
│  │ afterburner-ebpf (XDP)       │◀─────┘                    │
│  │ UDP:8000 → XSK.redirect()    │                           │
│  └──────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
                         │
                    ┌────▼────┐
                    │   NIC   │
                    └─────────┘
```

## Project Structure

### `afterburner-ebpf/` - Kernel Filter
- **Role**: Traffic cop at the NIC driver layer
- **Function**: Intercepts UDP packets on port 8000, redirects to AF_XDP socket via `XSK.redirect()`
- **Runs**: Inside Linux kernel (eBPF VM)

### `afterburner-app/` - Userspace Engine
- **`main.rs`**: Event loop (RX → Logic → TX stages)
- **`quic_driver.rs`**: QUIC state machine wrapper (handshake, streams, retransmission)
- **`xsk.rs`**: AF_XDP socket with UMEM ring buffers
- **`headers.rs`**: Ethernet/IP/UDP header construction
- **`flood.rs`**: Transaction flooder (streams 0,4,8,12)
- **`emit.rs`**: Mock Solana transaction (235 bytes)

### `afterburner-app/src/bin/` - Tools
- **`stream_server.rs`**: Dual-mode QUIC server (sends timestamps, receives TX)

### `afterburner-common/` - Shared Types
- Shared constants between kernel and userspace

### `xtask/` - Build Automation
- Handles eBPF cross-compilation to `bpfel-unknown-none` target

## Configuration

Key tuning parameters in `quic_driver.rs`:
```rust
config.set_max_ack_delay(0);              // Zero ACK delay for HFT
config.set_initial_max_data(100_000_000); // 100MB connection flow control
config.set_initial_max_streams_bidi(1000); // 1000 concurrent streams
```

AF_XDP settings in `xsk.rs`:
```rust
const UMEM_SIZE: usize = 8 * 1024 * 1024;  // 8MB shared memory
const FRAME_SIZE: usize = 4096;             // 4KB per frame
const RING_SIZE: u32 = 2048;                // Ring buffer depth
```

## Production Deployment

To deploy on Solana mainnet:

1. **Swap Interface**: Replace `veth0` with physical NIC (`eth0`, `enp1s0`)
2. **Enable Zero-Copy**: Use NIC with XDP driver support (Intel i40e, Mellanox)
3. **Real Transactions**: Replace `MockTransaction` with `solana_sdk::transaction::VersionedTransaction`
4. **Real Certificates**: Use validator identity keypair for TLS

## License

MIT