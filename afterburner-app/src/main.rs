mod xsk;

use anyhow::Context;
use aya::maps::XskMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Ebpf};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let args = Args::parse();

    println!("Starting Afterburner on interface {}", args.iface);

    // Load BPF Binary
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/afterburner"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/afterburner"
    ))?;

    // Load Program from Binary
    let program: &mut Xdp = bpf
        .program_mut("afterburner")
        .unwrap()
        .try_into()
        .context("Failed to load the XDP program")?;

    program.load()?;

    // Attach Program (Driver Mode -> Generic Fallback)
    println!("Attempting to attach in Driver Mode...");
    if program.attach(&args.iface, XdpFlags::default()).is_err() {
        program.attach(&args.iface, XdpFlags::SKB_MODE)?;
        println!("Attached in Generic Mode (Slower, but compatible).");
    } else {
        println!("Attached in Driver Mode (Hardware Speed).");
    }

    // Create AF_XDP Socket
    println!("Createing AF_XDP socket...");
    let mut socket = xsk::XdpSocket::new(&args.iface, 0).context("Failed to create XDP socket")?;

    // Connect Socket to BPF Map
    let mut xsk_map: XskMap<aya::maps::MapData> = bpf.take_map("XSK").unwrap().try_into()?;

    xsk_map
        .set(0, socket.fd(), 0)
        .context("Failed to insert socket into XSK Map")?;

    // We give the Kernel 2048 empty buffers *before* we start.
    // If we don't do this, the Kernel will drop incoming packets immediately.
    println!("Priming Fill Ring...");
    socket.populate_fill_ring(2048);

    println!("Afterburner is Live, Waiting for UDP packets on Port 8003...");

    // Run the Receive Loop
    let term = Arc::new(AtomicBool::new(false));
    let term_c = term.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        term_c.store(true, Ordering::Relaxed);
    });

    let mut packet_count = 0;

    while !term.load(Ordering::Relaxed) {
        // Poll for 1 packet
        match socket.poll_rx() {
            Some((_count, len)) => {
                packet_count += 1;
                print!(".");
                use std::io::Write;
                std::io::stdout().flush().unwrap();

                if packet_count % 100 == 0 {
                    println!(" [{} pkts, last size: {}]", packet_count, len);
                }
            }
            None => {
                // If no packets, Sleep 1ms to save CPU (Remove this line for max performance)
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    println!("Exiting Afterburner...");

    Ok(())
}
