use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use clap::Parser;
use aya::{programs::{Xdp, XdpFlags}, maps::XskMap, Ebpf};

mod xsk;
mod headers;
mod quic_driver;
mod emit;
mod flood;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    iface: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))?;

    println!("Starting Afterburner QUIC on: {}", args.iface);

    let ebpf_path = std::path::Path::new("target/bpfel-unknown-none/release/afterburner");
    let mut bpf = Ebpf::load_file(ebpf_path)?;
    
    let program: &mut Xdp = bpf.program_mut("afterburner").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.iface, XdpFlags::default())?;
    println!("[XDP] eBPF program attached to {}", args.iface);

    let mut socket = xsk::XdpSocket::new(&args.iface, 0)?;
    
    let mut xsk_map = XskMap::try_from(bpf.map_mut("XSK").unwrap())?;
    xsk_map.set(0, socket.fd, 0)?;
    println!("[XSK] AF_XDP socket registered");
    
    let local: SocketAddr = "10.0.0.10:8000".parse()?;
    let peer: SocketAddr = "10.0.0.11:8004".parse()?;
    let scid = [0x55; 20];
    let mut driver = quic_driver::QuicDriver::new(&scid, local, peer);
    let mut flooder = flood::Flooder::new();

    println!("[RUN] HFT Loop Running (Bidirectional Mode)");

    while !term.load(Ordering::Relaxed) {
        if let Some((addr, len)) = socket.poll_rx() {
            let ptr = unsafe { socket.umem_ptr.add(addr as usize) };
            let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
            if len > 42 {
                driver.process_input(&mut slice[42..], local, peer);
            }
        }

        driver.on_timeout();
        driver.drain_streams();
        flooder.shoot(&mut driver);

        while let Some(frame) = socket.get_tx_frame() {
            match driver.write_transmit(&mut frame[42..]) {
                Some(quic_len) if quic_len > 0 => {
                    headers::write_headers(frame, quic_len, 8000, 8004);
                    socket.tx_submit(42 + quic_len);
                },
                _ => {
                    socket.cancel_tx();
                    break;
                }
            }
        }
        
        std::hint::spin_loop(); 
    }

    println!("Shutting down. Total TX Sent: {}", flooder.tx_count);
    let _ = driver.conn.close(true, 0, b"done");
    
    for _ in 0..16 {
        if let Some(frame) = socket.get_tx_frame() {
            match driver.write_transmit(&mut frame[42..]) {
                Some(quic_len) if quic_len > 0 => {
                    headers::write_headers(frame, quic_len, 8000, 8004);
                    socket.tx_submit(42 + quic_len);
                },
                _ => {
                    socket.cancel_tx();
                    break;
                }
            }
        } else {
            break;
        }
    }
    
    Ok(())
}