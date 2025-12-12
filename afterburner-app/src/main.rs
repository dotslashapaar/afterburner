use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Ebpf};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/afterburner"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/afterburner"
    ))?;

    let program: &mut Xdp = bpf
        .program_mut("afterburner")
        .unwrap()
        .try_into()
        .context("Failed to load the XDP program")?;

    program.load()?;

    println!("Attempting to attach in Driver Mode...");
    match program.attach(&args.iface, XdpFlags::default()) {
        Ok(_) => println!("Success! Attached in Driver Mode (Hardware)."),
        Err(_) => {
            println!("Driver Mode failed (common on Wi-Fi). Retrying in Generic Mode (Software)...");
            program.attach(&args.iface, XdpFlags::SKB_MODE)
                .context(format!("Failed to attach XDP to {} in both Driver and Generic modes", args.iface))?;
            println!("Success! Attached in Generic Mode.");
        }
    }

    println!("Afterburner is running. Press Ctrl+C to stop.");

    let term = Arc::new(AtomicBool::new(false));
    signal::ctrl_c().await?;
    term.store(true, Ordering::Relaxed);

    println!("Exiting Afterburner...");

    Ok(())
}
