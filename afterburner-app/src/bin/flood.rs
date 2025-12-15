use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn main() {
    // 1. Bind to ephemeral port
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind");

    // 2. Connect (Locks the route for higher speed than send_to)
    // Target: Loopback 8003
    let target = "127.0.0.1:8003";
    socket.connect(target).expect("Failed to connect");

    // 3. Payload (100 bytes)
    let buf = [0u8; 100];

    println!("🌊 Starting High-Speed Flood to {}...", target);
    println!("Press Ctrl+C to stop.");

    let mut count = 0;
    let mut last_log = Instant::now();

    loop {
        // 'send' is faster than 'send_to' because the OS skips route lookup
        if let Err(_) = socket.send(&buf) {
            break;
        }

        count += 1;

        // Log stats sparingly (checking time is expensive)
        if count % 10000 == 0 {
            if last_log.elapsed() >= Duration::from_secs(1) {
                println!("Sender Speed: {} PPS", count);
                count = 0;
                last_log = Instant::now();
            }
        }
    }
}
