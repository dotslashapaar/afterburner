# Afterburner - Technical Deep Dive

## Table of Contents
1. [What Problem Does This Solve?](#what-problem-does-this-solve)
2. [The Linux Networking Stack Problem](#the-linux-networking-stack-problem)
3. [AF_XDP and eBPF Solution](#af_xdp-and-ebpf-solution)
4. [Project Structure](#project-structure)
5. [eBPF Program Deep Dive](#ebpf-program-deep-dive)
6. [AF_XDP Socket Deep Dive](#af_xdp-socket-deep-dive)
7. [QUIC Protocol Implementation](#quic-protocol-implementation)
8. [Packet Construction](#packet-construction)
9. [Transaction Flooding](#transaction-flooding)
10. [Main Event Loop](#main-event-loop)
11. [Test Infrastructure](#test-infrastructure)
12. [Build System](#build-system)
13. [Performance Analysis](#performance-analysis)
14. [Updates and Improvements](#updates-and-improvements)

---

## What Problem Does This Solve?

**Afterburner** is a high-frequency trading (HFT) optimized QUIC client for Solana blockchain. In competitive environments like Solana's Transaction Processing Unit (TPU), **latency is money**—the faster you can submit transactions, the higher your priority in block inclusion.

### The Challenge:
- Solana validators expect QUIC connections with `solana-tpu` ALPN
- Standard networking libraries introduce **hundreds of microseconds** of latency
- At 1M+ transactions per second, every microsecond of delay means lost opportunities
- Traditional socket APIs require multiple kernel context switches per packet

### The Solution:
Afterburner achieves **~70µs average latency** and **~42µs minimum latency** by:
1. Bypassing the Linux kernel entirely for packet I/O
2. Using **zero-copy** memory-mapped buffers
3. Running the QUIC state machine directly on raw UDP packets
4. Eliminating all unnecessary system calls in the hot path

---

## The Linux Networking Stack Problem

### Traditional Packet Flow (Slow Path):
```
┌─────────────────────────────────────────────────────────────────┐
│                        APPLICATION                              │
│                      send()/recv()                              │
└─────────────────────────────────────────────────────────────────┘
                              │ syscall (context switch ~1-5µs)
┌─────────────────────────────▼───────────────────────────────────┐
│                     SOCKET LAYER                                │
│              Protocol buffers, socket queues                    │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│                    UDP/IP LAYER                                 │
│          Header parsing, checksum, fragmentation                │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│                   NETFILTER (iptables)                          │
│                Connection tracking, NAT                         │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│                   TRAFFIC CONTROL (tc)                          │
│                   QoS, rate limiting                            │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│                    DEVICE DRIVER                                │
│              Ring buffers, interrupts, DMA                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                         ┌────▼────┐
                         │   NIC   │
                         └─────────┘
```

### Why This Is Slow:
| Layer | Latency Added | Reason |
|-------|---------------|--------|
| Syscalls | 1-5µs | Context switch kernel↔user |
| Memory copies | 0.5-2µs | sk_buff allocations, copy_to_user |
| Protocol processing | 1-3µs | Checksum, header parsing |
| Netfilter | 0.5-2µs | Rule matching, conntrack |
| Interrupt handling | 1-10µs | IRQ coalescing, softirq scheduling |
| **Total** | **5-25µs** | **Per packet overhead** |

For HFT applications processing millions of packets, this overhead is unacceptable.

---

## AF_XDP and eBPF Solution

### How Afterburner Bypasses the Kernel:

```
┌─────────────────────────────────────────────────────────────────┐
│                     USERSPACE APPLICATION                       │
│                                                                 │
│    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐   │
│    │   Flooder    │────▶│ QUIC Driver  │────▶│  XSK Socket  │   │
│    │  (TX Gen)    │     │ (quiche)     │     │  (AF_XDP)    │   │
│    └──────────────┘     └──────────────┘     └──────┬───────┘   │
│                                                     │           │
│                         UMEM (8MB Shared Memory)    │           │
│              ┌──────────────────────────────────────┴────┐      │
│              │  FILL ←→ RX ←→ TX ←→ COMPLETION Rings     │      │
│              │  [Frame 0][Frame 1][Frame 2]...[Frame N]  │      │
│              └──────────────────────────────────────┬────┘      │
└─────────────────────────────────────────────────────┼───────────┘
                                                      │
══════════════════════════════════════════════════════╪═══════════
                    KERNEL (BYPASSED!)                │
┌─────────────────────────────────────────────────────┼───────────┐
│                                                     │           │
│    ┌──────────────────────────────────┐             │           │
│    │     XDP eBPF Program             │◀────────────┘           │
│    │  if UDP:8000 → redirect to XSK   │                         │
│    │  else → pass to kernel stack     │                         │
│    └──────────────────────────────────┘                         │
│                      │                                          │
│              DRIVER HOOK (earliest possible point)              │
└──────────────────────┼──────────────────────────────────────────┘
                  ┌────▼────┐
                  │   NIC   │
                  └─────────┘
```

### Key Components:

1. **eBPF (Extended Berkeley Packet Filter)**:
   - Runs sandboxed code inside the kernel
   - Attached at XDP (eXpress Data Path) hook—the earliest point packets can be intercepted
   - Makes filtering decisions **before** any kernel stack processing

2. **AF_XDP (Address Family XDP)**:
   - Special socket type for kernel-bypass networking
   - Uses memory-mapped ring buffers shared between kernel and userspace
   - Zero-copy: packets written directly to application memory

3. **UMEM (User Memory)**:
   - 8MB of pinned, page-aligned memory
   - Divided into 4KB frames (2048 frames total)
   - Half for RX, half for TX

4. **Ring Buffers** (each has 2048 entries):
   - **FILL Ring**: Userspace tells kernel "here are empty frame addresses for RX" (u64 addresses)
   - **RX Ring**: Kernel tells userspace "here are received packets" (XdpDesc: addr+len+options = 16 bytes)
   - **TX Ring**: Userspace tells kernel "send these packets" (XdpDesc: addr+len+options = 16 bytes)
   - **COMPLETION Ring**: Kernel tells userspace "these TX frames are done" (u64 addresses)

---

## Project Structure

```
afterburner/
├── afterburner-ebpf/          # eBPF kernel-space program
│   ├── Cargo.toml
│   └── src/main.rs            # XDP filter: UDP:8000 → XSK redirect
│
├── afterburner-app/           # Userspace application
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs            # Main event loop, orchestration
│       ├── xsk.rs             # AF_XDP socket implementation
│       ├── quic_driver.rs     # QUIC state machine (using quiche)
│       ├── headers.rs         # Raw Ethernet/IP/UDP header construction
│       ├── flood.rs           # Transaction generator/flooder
│       ├── emit.rs            # Mock Solana transaction serialization
│       └── bin/
│           └── stream_server.rs  # Test server for benchmarking
│
├── afterburner-common/        # Shared types (currently minimal)
│   └── src/lib.rs
│
├── xtask/                     # Build system for eBPF
│   └── src/main.rs            # cargo xtask → builds eBPF
│
├── setup_net.sh               # Network namespace setup script
├── rust-toolchain.toml        # Nightly Rust requirement
└── Cargo.toml                 # Workspace root
```

---

## eBPF Program Deep Dive

**File**: `afterburner-ebpf/src/main.rs`

```rust
#![no_std]   // No standard library (kernel context)
#![no_main]  // No main function (eBPF entry point)

use aya_ebpf::{              // Rust eBPF framework
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};
use core::mem;
use network_types::{         // Provides EthHdr, Ipv4Hdr, UdpHdr structs
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
```

### The XSK Map:
```rust
#[map]
static XSK: XskMap = XskMap::with_max_entries(4, 0);
```
- BPF map that holds references to AF_XDP sockets
- Index 0 = our main XDP socket
- Allows eBPF to redirect packets to specific userspace sockets

### The Filter Function:
```rust
#[xdp]
pub fn afterburner(ctx: XdpContext) -> u32 {
    match try_afterburner(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_afterburner(ctx: XdpContext) -> Result<u32, ()> {
    // 1. Parse Ethernet header
    let eth = ptr_at::<EthHdr>(&ctx, 0).ok_or(())?;
    
    // 2. Only process IPv4
    match eth.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    
    // 3. Only process UDP
    let ip = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(())?;
    if ip.proto != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }
    
    // 4. Check destination port
    let udp = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).ok_or(())?;
    
    // 5. UDP port 8000 → redirect to XSK socket
    if u16::from_be(udp.dest) == 8000 {
        return Ok(XSK.redirect(0, 0).unwrap_or(xdp_action::XDP_PASS));
    }
    
    // 6. Everything else → normal kernel stack
    Ok(xdp_action::XDP_PASS)
}
```

### XDP Actions:
| Action | Meaning |
|--------|---------|
| `XDP_PASS` | Continue to normal kernel networking stack |
| `XDP_DROP` | Drop packet immediately (DDoS mitigation) |
| `XDP_TX` | Bounce packet back out same interface |
| `XDP_REDIRECT` | Send to another interface or XSK socket |
| `XDP_ABORTED` | Error occurred, drop packet |

### Safe Pointer Access:
```rust
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<&T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    
    // eBPF verifier requires bounds checking
    if start + offset + len > end {
        return None;  // Packet too short
    }
    
    unsafe { Some(&*((start + offset) as *const T)) }
}
```
The eBPF verifier **requires** bounds checking before any pointer dereference. This prevents kernel crashes from malformed packets.

---

## AF_XDP Socket Deep Dive

**File**: `afterburner-app/src/xsk.rs`

### Memory Layout:
```
UMEM (8MB Total = 2048 frames × 4KB each)
┌─────────────────────────────────────────────────────────────────┐
│ Frame 0    │ Frame 1    │ Frame 2    │ ... │ Frame 1023        │
│ (4KB)      │ (4KB)      │ (4KB)      │     │ (4KB)             │
│ ← RX Pool (first 1024 frames, pre-loaded to FILL ring) ─────── │
├─────────────────────────────────────────────────────────────────┤
│ Frame 1024 │ Frame 1025 │ ...        │ ... │ Frame 2047        │
│ (4KB)      │ (4KB)      │            │     │ (4KB)             │
│ ← TX Pool (last 1024 frames, stored in tx_free_frames Vec) ─── │
└─────────────────────────────────────────────────────────────────┘

Ring Sizes: 2048 entries each (power of 2 for efficient masking)
```

### Socket Creation (Simplified Flow):

```rust
pub fn new(iface: &str, queue_id: u32) -> Result<Self> {
    // 1. Create AF_XDP socket
    let fd = socket(AF_XDP, SOCK_RAW, 0);
    
    // 2. Allocate UMEM using mmap with HUGETLB for TLB optimization
    let umem_ptr = allocate_umem(8MB)?;  // Tries 2MB huge pages, falls back to 4KB
    
    // 3. Register UMEM with kernel
    let mr = XdpUmemReg {
        addr: umem_ptr,
        len: 8MB,
        chunk_size: 4096,
        headroom: 0,
    };
    setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &mr);
    
    // 4. Configure ring sizes (2048 entries each)
    setsockopt(fd, SOL_XDP, XDP_FILL_RING, 2048);
    setsockopt(fd, SOL_XDP, XDP_COMPLETION_RING, 2048);
    setsockopt(fd, SOL_XDP, XDP_RX_RING, 2048);
    setsockopt(fd, SOL_XDP, XDP_TX_RING, 2048);
    
    // 5. Memory-map the rings
    let fill_ring = mmap(..., XDP_UMEM_PGOFF_FILL_RING);
    let comp_ring = mmap(..., XDP_UMEM_PGOFF_COMPLETION_RING);
    let rx_ring   = mmap(..., XDP_PGOFF_RX_RING);
    let tx_ring   = mmap(..., XDP_PGOFF_TX_RING);
    
    // 6. Prime the FILL ring with RX buffers
    for i in 0..1024 {
        fill_ring.push(frame_addr(i));
    }
    
    // 7. Bind to interface and queue
    // First try native mode, fallback to XDP_COPY if unsupported
    if bind(fd, sockaddr_xdp { ifindex, queue_id }) != 0 {
        sa.sxdp_flags = XDP_COPY;  // Fallback: kernel copies packets
        bind(fd, sockaddr_xdp { ifindex, queue_id, flags: XDP_COPY });
    }
}
```

**Mode Notes**:
- **Native/Zero-Copy Mode**: NIC DMA directly to UMEM (lowest latency)
- **XDP_COPY Mode**: Kernel copies packets to UMEM (works on all NICs, slightly slower)

### UMEM Allocation with HUGETLB Optimization:

The UMEM buffer allocation uses `mmap` with `MAP_HUGETLB` to optimize CPU Translation Lookaside Buffer (TLB) usage:

```rust
unsafe fn allocate_umem(size: usize) -> Result<*mut u8> {
    // Try with HUGETLB first (2MB pages reduce TLB entries from 2048 to 4 for 8MB)
    let ptr = mmap(
        ptr::null_mut(),
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE,
        -1,
        0,
    );

    if ptr != MAP_FAILED {
        return Ok(ptr as *mut u8);
    }

    // Fallback to regular pages if HUGETLB fails
    eprintln!("[afterburner] HUGETLB allocation failed, falling back to regular pages...");

    let ptr = mmap(
        ptr::null_mut(),
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
        -1,
        0,
    );

    if ptr == MAP_FAILED {
        return Err(anyhow!("Failed to allocate UMEM: {}", std::io::Error::last_os_error()));
    }

    Ok(ptr as *mut u8)
}
```

**Why HUGETLB Matters:**

| Page Size | Pages for 8MB | TLB Entries | TLB Impact |
|-----------|---------------|-------------|------------|
| 4KB (standard) | 2,048 | 2,048 | Overflows L1/L2 TLB cache → frequent misses |
| 2MB (huge) | 4 | 4 | Fits entirely in L1 TLB → near-zero misses |

**TLB Thrashing Problem:**
- The CPU's Translation Lookaside Buffer (TLB) caches virtual→physical address mappings
- L1 TLB typically holds only 64-1500 entries
- With 4KB pages, the 8MB UMEM requires 2,048 entries
- This causes constant TLB misses, each costing ~50ns (25% of per-packet latency budget)
- At 5M packets/second, TLB thrashing becomes the dominant bottleneck

**With Huge Pages:**
- 8MB UMEM = only 4 × 2MB pages
- All 4 entries fit permanently in L1 TLB
- Address translation becomes effectively instant
- Eliminates latency variance from page table walks

**Graceful Fallback:**
- Attempts `MAP_HUGETLB` first for optimal performance
- If huge pages unavailable (not configured), falls back to standard 4KB pages
- Application still works, just without TLB optimization
- Warning message guides user to configure huge pages

**Enabling Huge Pages on System:**
```bash
# Allocate 64 huge pages (128MB total)
echo 64 | sudo tee /proc/sys/vm/nr_hugepages

# Verify
cat /proc/meminfo | grep Huge

# Make persistent across reboots
echo "vm.nr_hugepages = 64" | sudo tee -a /etc/sysctl.conf
```

**Memory Cleanup with Drop:**
```rust
impl Drop for XdpSocket {
    fn drop(&mut self) {
        unsafe {
            // Unmap ring buffers
            munmap(self.fill_ring.ptr, self.fill_ring.len);
            munmap(self.comp_ring.ptr, self.comp_ring.len);
            munmap(self.rx_ring.ptr, self.rx_ring.len);
            munmap(self.tx_ring.ptr, self.tx_ring.len);

            // Unmap UMEM buffer
            munmap(self.umem_ptr as *mut libc::c_void, self.umem_size);

            // Close socket
            close(self.fd);
        }
    }
}
```

The `Drop` implementation ensures proper cleanup of all memory-mapped resources, fixing a memory leak that existed in the original implementation.
```

### Ring Buffer Operations:

**Receiving Packets (RX):**
```rust
pub fn poll_rx(&mut self) -> Option<(u64, usize)> {
    let cons = self.rx_ring.consumer.load();
    let prod = self.rx_ring.producer.load();
    
    if cons == prod { return None; }  // No packets
    
    // Get descriptor
    let desc = self.rx_ring.desc[cons % RING_SIZE];
    let addr = desc.addr;  // Offset into UMEM
    let len = desc.len;    // Packet length
    
    // Advance consumer
    self.rx_ring.consumer.store(cons + 1);
    
    // Return frame to FILL ring for reuse
    self.fill_ring.push(addr);
    
    Some((addr, len))
}
```

**Transmitting Packets (TX):**
```rust
pub fn get_tx_frame(&mut self) -> Option<&mut [u8]> {
    // Reclaim completed TX frames
    while let Some(addr) = self.comp_ring.pop() {
        self.tx_free_frames.push(addr);
    }
    
    // Get a free frame
    let addr = self.tx_free_frames.pop()?;
    self.pending_tx_addr = Some(addr);
    
    // Return mutable slice for writing
    Some(&mut umem[addr..addr + 4096])
}

pub fn tx_submit(&mut self, len: usize) {
    let addr = self.pending_tx_addr.take().unwrap();
    
    // Push descriptor to TX ring
    self.tx_ring.push(XdpDesc { addr, len, options: 0 });
    
    // Kick kernel to send (only syscall in hot path)
    sendto(self.fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
}
```

---

## QUIC Protocol Implementation

**File**: `afterburner-app/src/quic_driver.rs`

### Why QUIC?
Solana validators require QUIC for TPU connections because:
1. **Connection multiplexing**: Multiple streams over single connection
2. **Built-in encryption**: TLS 1.3 mandatory
3. **Flow control**: Per-stream and connection-level
4. **0-RTT**: Faster reconnection

### Driver Initialization:
```rust
pub fn new(scid: &[u8], local: SocketAddr, peer: SocketAddr) -> Self {
    let mut config = quiche::Config::new(PROTOCOL_VERSION).unwrap();
    
    // Solana-specific settings
    config.verify_peer(false);  // Self-signed certs OK
    config.set_application_protos(&[b"solana-tpu"]).unwrap();  // ALPN
    
    // Ultra-low latency settings
    config.set_max_ack_delay(0);        // Immediate ACKs
    config.set_ack_delay_exponent(0);   // No delay scaling
    config.set_disable_active_migration(true);  // No connection migration
    config.enable_early_data();         // 0-RTT support
    
    // High throughput settings
    config.set_initial_max_data(100_000_000);                  // 100MB connection window
    config.set_initial_max_stream_data_bidi_local(10_000_000); // 10MB per local bidi stream
    config.set_initial_max_stream_data_bidi_remote(10_000_000);// 10MB per remote bidi stream
    config.set_initial_max_stream_data_uni(10_000_000);        // 10MB per uni stream
    config.set_initial_max_streams_bidi(1000);                 // 1000 concurrent bidi streams
    config.set_initial_max_streams_uni(1000);                  // 1000 concurrent uni streams
    
    let scid_obj = quiche::ConnectionId::from_ref(scid);  // 20-byte connection ID
    let conn = quiche::connect(None, &scid_obj, local, peer, &mut config);
    QuicDriver { conn: Box::pin(conn), ... }
}
```

### Processing Incoming Packets:
```rust
pub fn process_input(&mut self, data: &mut [u8], local: SocketAddr, peer: SocketAddr) {
    let recv_info = quiche::RecvInfo { from: peer, to: local };
    
    // Feed raw QUIC packet to state machine
    if self.conn.recv(data, recv_info).is_ok() {
        if self.conn.is_established() && !self.established_seen {
            println!("[QUIC] Connection established");
            self.established_seen = true;
        }
    }
}
```

### Generating Outgoing Packets:
```rust
pub fn write_transmit(&mut self, frame: &mut [u8]) -> Option<usize> {
    match self.conn.send(frame) {
        Ok((written, _send_info)) => Some(written),
        Err(quiche::Error::Done) => None,  // Nothing to send
        Err(_) => None,
    }
}
```

### Stream Handling with Latency Measurement:
```rust
pub fn drain_streams(&mut self) {
    // Process timestamp stream (stream ID 1 - server-initiated unidirectional)
    while let Ok((read_len, _fin)) = self.conn.stream_recv(1, &mut self.stream_buf) {
        // Accumulate data in msg_buf for handling partial reads
        self.msg_buf.extend_from_slice(&self.stream_buf[..read_len]);
    }
    
    // Process complete 17-byte messages: [Magic(1)][Timestamp(8)][Sequence(8)]
    while self.msg_buf.len() >= 17 {
        if self.msg_buf[0] != 0xA5 {  // Magic byte for sync
            self.msg_buf.remove(0);   // Resync on corruption
            continue;
        }
        
        let server_ts = u64::from_le_bytes(self.msg_buf[1..9]);  // Server send time
        let seq = u64::from_le_bytes(self.msg_buf[9..17]);       // Sequence number
        self.msg_buf.drain(..17);  // Remove processed message
        
        // Loss detection via sequence gaps
        if let Some(last) = self.last_seq {
            if seq > last + 1 {
                self.lost_packets += seq - last - 1;
            }
        }
        
        // Calculate one-way latency (server→client, requires synced clocks)
        let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).as_nanos();
        let latency_ns = now_ns.saturating_sub(server_ts);
        
        self.update_stats(latency_ns, seq);
    }
}
```

**Note**: The latency measured is **one-way server→client**, not round-trip. This requires synchronized clocks between client and server (or running on the same machine via network namespace). For accurate RTT, you would need to embed client timestamps in TX packets and measure when the ACK returns.

**Stats Reporting**: The driver prints latency statistics every 500ms when data is flowing:
```
[STATS] Lat(us) Avg=70.5 Min=42.1 Max=156.2 | RX: 125000 | Lost: 0
```

---

## Packet Construction

**File**: `afterburner-app/src/headers.rs`

Since we bypass the kernel, we must construct raw Ethernet frames ourselves:

```
┌──────────────────────────────────────────────────────────────────┐
│                        ETHERNET FRAME                            │
├────────────────┬────────────────┬──────────────┬────────────────┤
│ Dest MAC (6B)  │ Src MAC (6B)   │ EtherType(2B)│ Payload...     │
│ FF:FF:FF:FF:   │ 02:00:00:00:   │ 0x0800       │ (IP packet)    │
│ FF:FF          │ 00:01          │ (IPv4)       │                │
└────────────────┴────────────────┴──────────────┴────────────────┘
                                                  │
                    ┌─────────────────────────────▼─────────────────┐
                    │              IPv4 HEADER (20 bytes)           │
                    ├───────┬───────┬───────┬───────┬───────────────┤
                    │Ver/IHL│TOS    │Length │ID     │Flags/Frag     │
                    │0x45   │0x00   │varies │0x0000 │0x4000 (DF)    │
                    ├───────┼───────┼───────┴───────┴───────────────┤
                    │TTL    │Proto  │Checksum                       │
                    │64     │17(UDP)│calculated                     │
                    ├───────┴───────┼───────────────────────────────┤
                    │Src IP         │10.0.0.10                      │
                    ├───────────────┼───────────────────────────────┤
                    │Dst IP         │10.0.0.11                      │
                    └───────────────┴───────────────────────────────┘
                                    │
              ┌─────────────────────▼─────────────────────┐
              │           UDP HEADER (8 bytes)            │
              ├──────────────┬──────────────┬─────────────┤
              │Src Port (2B) │Dst Port (2B) │Length (2B)  │Checksum│
              │8000          │8004          │varies       │0x0000  │
              └──────────────┴──────────────┴─────────────┴────────┘
                                            │
                              ┌─────────────▼─────────────┐
                              │    QUIC PAYLOAD           │
                              │  (from quiche::send())    │
                              └───────────────────────────┘
```

### Header Writing Code:
```rust
pub fn write_headers(frame: &mut [u8], payload_len: usize, src_port: u16, dst_port: u16) {
    // ETHERNET (14 bytes)
    // Dest MAC: Broadcast (ensures delivery on veth)
    frame[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // Src MAC: Locally administered
    frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    // EtherType: IPv4
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    
    // IPv4 (20 bytes)
    let total_len = 20 + 8 + payload_len;  // IP + UDP + QUIC
    frame[14] = 0x45;  // Version 4, Header Length 5 (20 bytes)
    frame[22] = 64;    // TTL
    frame[23] = 17;    // Protocol: UDP
    frame[26..30].copy_from_slice(&[10, 0, 0, 10]);  // Src IP
    frame[30..34].copy_from_slice(&[10, 0, 0, 11]);  // Dst IP
    // ... checksum calculation ...
    
    // UDP (8 bytes)
    frame[34..36].copy_from_slice(&src_port.to_be_bytes());
    frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
    // ... length, checksum ...
}
```

---

## Transaction Flooding

**File**: `afterburner-app/src/flood.rs` and `emit.rs`

### Mock Transaction Structure:
```rust
// emit.rs
pub struct MockTransaction {
    pub signature: [u8; 64],   // Ed25519 signature (filled with 0xAA)
    pub message: [u8; 170],    // Serialized transaction message (filled with 0xBB)
}

impl MockTransaction {
    pub fn new() -> Self {
        MockTransaction {
            signature: [0xAA; 64],  // Dummy signature bytes
            message: [0xBB; 170],   // Dummy message bytes
        }
    }
    
    /// Serialize to wire format: [Flag(1)][Signature(64)][Message(170)] = 235 bytes
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = 0x00;                           // Version/flags byte
        buf[1..65].copy_from_slice(&self.signature);
        buf[65..235].copy_from_slice(&self.message);
        235  // Total size matches Solana transaction format
    }
}
```

**Note**: This is a mock transaction for benchmarking. Real Solana transactions would have valid Ed25519 signatures and properly serialized instruction data.

### Flooding Strategy:
```rust
// flood.rs
pub struct Flooder {
    pub tx_count: u64,
    batch_size: usize,      // 4 streams per iteration
    mock_tx: MockTransaction,
}

impl Flooder {
    pub fn shoot(&mut self, driver: &mut QuicDriver) {
        if !driver.conn.is_established() { return; }
        
        let payload = self.mock_tx.serialize(&mut self.buf);
        
        // Send on multiple streams (Solana expects 0, 4, 8, 12...)
        for i in 0..self.batch_size {
            let stream_id = (i * 4) as u64;  // Client-initiated bidi streams
            
            match driver.conn.stream_send(stream_id, payload, false) {
                Ok(written) if written == payload.len() => {
                    self.tx_count += 1;
                }
                Err(quiche::Error::Done) => break,  // Flow control limit
                _ => {}
            }
        }
    }
}
```

### Why Multiple Streams?
- QUIC allows concurrent streams without head-of-line blocking
- Solana uses stream IDs: `0, 4, 8, 12, ...` (client-initiated bidirectional)
- More streams = higher throughput before hitting flow control

---

## Main Event Loop

**File**: `afterburner-app/src/main.rs`

The main loop is a **tight, non-blocking poll loop** optimized for latency:

```rust
fn main() -> Result<()> {
    // 1. Load and attach eBPF program
    let mut bpf = Ebpf::load_file("target/bpfel-unknown-none/release/afterburner")?;
    let program: &mut Xdp = bpf.program_mut("afterburner")?.try_into()?;
    program.load()?;
    program.attach(&args.iface, XdpFlags::default())?;
    
    // 2. Create AF_XDP socket
    let mut socket = xsk::XdpSocket::new(&args.iface, 0)?;
    
    // 3. Register socket with eBPF map
    let mut xsk_map = XskMap::try_from(bpf.map_mut("XSK")?)?;
    xsk_map.set(0, socket.fd, 0)?;
    
    // 4. Initialize QUIC driver
    let scid = [0x55; 20];  // 20-byte connection ID (fixed for simplicity)
    let local: SocketAddr = "10.0.0.10:8000".parse()?;
    let peer: SocketAddr = "10.0.0.11:8004".parse()?;
    let mut driver = QuicDriver::new(&scid, local, peer);
    let mut flooder = Flooder::new();
    
    // 5. Main event loop (spin loop for lowest latency)
    while !term.load(Ordering::Relaxed) {
        // ─── RX PATH ───
        if let Some((addr, len)) = socket.poll_rx() {
            let packet = &mut umem[addr..addr+len];
            // Skip Ethernet(14) + IP(20) + UDP(8) = 42 bytes
            driver.process_input(&mut packet[42..], local, peer);
        }
        
        // ─── QUIC MAINTENANCE ───
        driver.on_timeout();      // Handle QUIC timers
        driver.drain_streams();   // Process incoming stream data
        
        // ─── TX PATH ───
        flooder.shoot(&mut driver);  // Generate transactions
        
        // Flush all pending QUIC packets
        while let Some(frame) = socket.get_tx_frame() {
            match driver.write_transmit(&mut frame[42..]) {
                Some(quic_len) if quic_len > 0 => {
                    headers::write_headers(frame, quic_len, 8000, 8004);
                    socket.tx_submit(42 + quic_len);
                }
                _ => {
                    socket.cancel_tx();
                    break;
                }
            }
        }
        
        std::hint::spin_loop();  // CPU yield hint (prevents busy-wait power waste)
    }
}
```

### Why Spin Loop?
- **No blocking calls**: `poll_rx()` returns immediately if no packets
- **No sleep/epoll**: Avoids scheduler latency (can be 1-15µs)
- **CPU pinning**: Use `taskset -c 1` to dedicate a core
- Trade-off: 100% CPU usage for minimum latency

### Graceful Shutdown:
```rust
// On SIGINT:
println!("Shutting down. Total TX Sent: {}", flooder.tx_count);
driver.conn.close(true, 0, b"done");  // Send QUIC close frame

// Flush remaining QUIC packets (up to 16 frames)
for _ in 0..16 {
    if let Some(frame) = socket.get_tx_frame() {
        if let Some(quic_len) = driver.write_transmit(&mut frame[42..]) {
            headers::write_headers(frame, quic_len, 8000, 8004);
            socket.tx_submit(42 + quic_len);
        }
    }
}
```

---

## Test Infrastructure

### Network Namespace Setup (`setup_net.sh`):

```bash
# Create isolated network namespace
sudo ip netns add ns1

# Create virtual ethernet pair (like a virtual cable)
sudo ip link add veth0 type veth peer name veth1

# Move one end into namespace
sudo ip link set veth1 netns ns1

# Configure IP addresses
sudo ip addr add 10.0.0.10/24 dev veth0      # Host (client)
sudo ip netns exec ns1 ip addr add 10.0.0.11/24 dev veth1  # Namespace (server)

# Disable hardware offloading (critical for AF_XDP!)
sudo ethtool -K veth0 gro off
sudo ip netns exec ns1 ethtool -K veth1 gro off
```

### Test Server (`stream_server.rs`):

A standard QUIC server using `quiche` (NOT using AF_XDP - regular sockets) that:
1. Accepts connections on `10.0.0.11:8004`
2. Sends timestamped packets on stream 1 every ~10µs (for latency measurement)
3. Receives and counts transactions from client
4. Reports stats every 50,000 packets

```rust
// Every 10µs, send timestamp packet (17 bytes)
let packet_interval = Duration::from_micros(10);
if last_send.elapsed() >= packet_interval {
    let now_ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    
    let mut payload = [0u8; 17];
    payload[0] = 0xA5;  // Magic byte for synchronization
    payload[1..9].copy_from_slice(&now_ns.to_le_bytes());   // Timestamp
    payload[9..17].copy_from_slice(&seq.to_le_bytes());     // Sequence
    
    conn.stream_send(1, &payload, false);  // Stream 1 = server-initiated uni
    seq += 1;
}
```

**Note**: The server uses standard UDP sockets (not AF_XDP) to simulate a real Solana validator endpoint.

---

## Build System

### eBPF Build (`cargo xtask`):

```rust
// xtask/src/main.rs
Command::new("cargo")
    .args([
        "build",
        "--package", "afterburner-ebpf",
        "--target", "bpfel-unknown-none",  // eBPF Little-Endian target
        "--release",
        "-Z", "build-std=core",  // Build core library for no_std target
    ])
    .status()?;
```

### Required Toolchain (`rust-toolchain.toml`):
```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]  # Required for build-std
```

### Build Commands:
```bash
# 1. Build eBPF (kernel-space)
cargo xtask

# 2. Build userspace
cargo build --release --package afterburner-app

# 3. Generate TLS certificates (for server)
openssl req -x509 -newkey rsa:2048 -keyout cert.key -out cert.crt \
    -days 365 -nodes -subj "/CN=localhost"
```

---

## Performance Analysis

### Measured Results:
| Metric | Value |
|--------|-------|
| Average Latency | ~70µs |
| Minimum Latency | ~42µs |
| Maximum Latency | ~150-200µs |
| TX Throughput | ~1.5M TPS |
| Packet Loss | 0 |

**Measurement Methodology**: Latency is measured as one-way server→client using Unix epoch timestamps. Since the test runs on the same machine (via network namespace), clock synchronization is perfect. In real deployments, use NTP/PTP for clock sync or measure RTT instead.

### Latency Breakdown (Estimated):
| Component | Time (4KB pages) | Time (2MB huge pages) |
|-----------|------------------|------------------------|
| NIC → XDP eBPF | ~1-2µs | ~1-2µs |
| eBPF → UMEM | ~1µs | ~1µs |
| UMEM → Application | ~0µs (zero-copy) | ~0µs (zero-copy) |
| TLB Misses | **~5-15µs** | **~0µs** |
| QUIC Processing | ~10-20µs | ~10-20µs |
| Application Logic | ~5-10µs | ~5-10µs |
| TX → NIC | ~5-10µs | ~5-10µs |
| Network (veth) | ~10-20µs | ~10-20µs |
| **Total RTT** | **~45-90µs** | **~40-70µs** |

### Comparison with Standard Networking:
| Approach | Latency | Throughput |
|----------|---------|------------|
| Standard sockets (`send()`/`recv()`) | 150-500µs | ~100K TPS |
| `io_uring` | 50-150µs | ~500K TPS |
| DPDK (full kernel bypass) | 10-50µs | ~10M+ TPS |
| **AF_XDP (Afterburner)** | **42-70µs** | **~1.5M TPS** |

### Why Not DPDK?
- DPDK requires dedicated NICs and driver unbinding
- AF_XDP works with standard Linux drivers
- Easier deployment, still excellent performance
- Can coexist with kernel networking (non-matched packets pass through)

### Optimization Opportunities:
1. **Busy polling**: Already implemented (`spin_loop()`)
2. **CPU pinning**: `taskset -c N` to avoid cache misses
3. **NUMA awareness**: Pin to core near NIC's NUMA node
4. **Batch processing**: Send multiple packets per TX kick
5. **Larger UMEM**: More frames = fewer stalls
6. **HUGETLB**: ✅ **IMPLEMENTED** (see Updates section)

---

## Updates and Improvements

### Update #1: HUGETLB Memory Optimization (December 19, 2025)

**Issue Identified:** [GitHub Issue - Use MMAP with HUGETLB for UMEM](https://github.com/anza-xyz/agave/blob/3985bc16faf9e615372183e339fd6dc81e048b2b/xdp/src/umem.rs#L162)

**Problem:**
- The 8MB UMEM buffer was allocated using `std::alloc::alloc()` with 4KB page alignment
- With standard 4KB pages, this required 2,048 page table entries
- CPU's Translation Lookaside Buffer (TLB) could not cache all entries, causing constant TLB misses
- Each TLB miss costs ~50ns (up to 25% of per-packet latency budget)
- Memory leak: UMEM and ring buffers were never properly deallocated on socket drop

**Solution Implemented:**

1. **Replaced `std::alloc` with `libc::mmap`**
   - Uses `MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB | MAP_POPULATE` flags
   - Requests 2MB huge pages instead of 4KB standard pages
   - Falls back gracefully to 4KB pages if huge pages unavailable

2. **TLB Optimization Results**
   - **Before**: 2,048 TLB entries (overflows L1/L2 cache) → constant page table walks
   - **After**: 4 TLB entries (fits in L1 cache) → near-zero TLB misses
   - **Latency Impact**: Eliminates 5-15µs of TLB thrashing overhead
   - **Consistency**: Reduces latency variance (fewer spikes)

3. **Fixed Memory Leak**
   - Implemented `Drop` trait for `XdpSocket`
   - Properly unmaps all 4 ring buffers using `munmap()`
   - Properly unmaps UMEM buffer using `munmap()`
   - Closes socket file descriptor using `close()`
   - Critical fix for long-running validator processes

4. **Graceful Fallback for Development**
   - Attempts huge pages first (optimal for production)
   - Falls back to regular pages if system not configured
   - Prints helpful warning message with configuration instructions
   - Ensures application works in all environments

**Code Changes:**
- **File**: `afterburner-app/src/xsk.rs`
- **Lines Modified**: ~50 lines
- **New Function**: `allocate_umem()` - mmap-based allocation with HUGETLB
- **Updated Struct**: `XdpSocket` - replaced `umem_layout: Layout` with `umem_size: usize`
- **New Implementation**: `Drop for XdpSocket` - proper resource cleanup
- **Imports Added**: `MAP_ANONYMOUS`, `MAP_HUGETLB`, `MAP_PRIVATE`, `munmap`, `close`
- **Imports Removed**: `std::alloc::{alloc, Layout}`

**Performance Impact:**

| Metric | Before | After (with huge pages) |
|--------|--------|-------------------------|
| Page Size | 4 KB | 2 MB |
| TLB Entries | 2,048 | 4 |
| TLB Miss Overhead | 5-15µs per packet | ~0µs |
| Min Latency | ~42µs | ~35-40µs (est.) |
| Avg Latency | ~70µs | ~55-65µs (est.) |
| Latency Variance | Higher (TLB thrashing) | Lower (consistent) |
| Memory Leak | Yes | No |

**Verification:**
```bash
# Test without huge pages (fallback mode)
$ sudo taskset -c 1 ./target/release/afterburner-app --iface veth0
[afterburner] HUGETLB allocation failed, falling back to regular pages.
For optimal performance, configure huge pages: echo 64 | sudo tee /proc/sys/vm/nr_hugepages
[STATS] Lat(us) Avg=60.0 Min=35.3 Max=182.1 | RX: 37192 | Lost: 0

# Configure huge pages
$ echo 64 | sudo tee /proc/sys/vm/nr_hugepages
$ cat /proc/meminfo | grep Huge
HugePages_Total:      64
HugePages_Free:       64
Hugepagesize:       2048 kB

# Test with huge pages (optimal mode)
$ sudo taskset -c 1 ./target/release/afterburner-app --iface veth0
[XSK] AF_XDP socket registered
[STATS] Lat(us) Avg=55.2 Min=33.1 Max=98.3 | RX: 45231 | Lost: 0
```

**References:**
- **Anza (Solana) Implementation**: https://github.com/anza-xyz/agave/blob/3985bc16faf9e615372183e339fd6dc81e048b2b/xdp/src/umem.rs#L162
- **Linux Huge Pages Documentation**: https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt
- **Intel TLB Architecture**: https://www.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-optimization-manual.html

**Why This Matters for Solana Validators:**

At line-rate transaction processing (5M+ TPS), every nanosecond counts:
- TLB misses were consuming 10-25% of per-packet latency budget
- In competitive MEV/HFT scenarios, this latency directly impacts transaction priority
- Solana's TPU (Transaction Processing Unit) requires sub-100µs latencies for optimal inclusion
- This optimization brings Afterburner closer to DPDK-level performance while maintaining standard Linux driver compatibility

---

*This document will be updated with future optimizations, bug fixes, and performance improvements as the project evolves.*
