# Afterburner 

**Afterburner** is a high-frequency trading (HFT) networking engine for Solana built in Rust. It utilizes **eBPF** and **AF_XDP** to bypass the Linux Kernel networking stack, achieving sub-microsecond latency and zero-copy packet processing.

## Quick Start \& Commands

### Build the Project

First, compile the Kernel-space (eBPF) program, then the User-space application.

```bash
# 1. Build the eBPF Kernel Probe
cargo build --package xtask --release

# 2. Build the User-space Engine & Tools
cargo build --release --package afterburner-app
```


### Run the Engine (Receiver)

This starts the AF_XDP socket. It will capture UDP traffic on port 8003.

```bash
# Replace 'lo' with 'eth0' or 'wlp4s0' for real hardware
sudo ./target/release/afterburner-app --iface lo
```


### Run the Tools (Senders)

Open a second terminal to generate traffic.

#### Option A: The Benchmarker (Speed Test)

Blasts raw UDP packets to test throughput (PPS).

```bash
cargo run --release --bin flood
```


#### Option B: The Inspector (Parser Test)

Sends structured Solana transactions (with Signatures and Instructions) to test the Zero-Copy parser.

```bash
cargo run --bin emit
```


## Architecture \& Workspaces

This project is a hybrid system spanning User Space and Kernel Space.

### 1. `afterburner-ebpf` (The Kernel Filter)

- **Role:** The Traffic Cop
- **Location:** Runs inside the Linux Kernel (Network Driver layer)
- **Function:** Intercepts incoming packets on the NIC. If the packet matches our criteria (UDP Port 8003), it redirects it directly to user memory (UMEM), completely bypassing the OS networking stack


### 2. `afterburner-app` (The Engine)

- **Role:** The Brain
- **Location:** Runs in User Space
- **Function:** Allocates the shared memory (UMEM) and spins on a high-speed poll loop. It reads raw bytes directly from RAM and uses Zero-Copy parsing to extract Solana transaction data (Signatures, Instructions) without memory allocation overhead


### 3. `afterburner-common`

- **Role:** The Translator
- **Function:** A shared library containing data structures and constants (like header sizes or config structs) used by both the Kernel probe and the User app to ensure they speak the same language


### 4. `xtask`

- **Role:** The Builder
- **Function:** An automation tool. Compiling eBPF code requires specific target architectures (bpfel-unknown-none). xtask handles the complex compiler flags and file placement to ensure the BPF probe is built correctly

---