use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind");
    let target = "127.0.0.1:8003";

    println!("Sending structured Solana packets to {}...", target);

    // Construct a Mock Transaction
    let mut packet = Vec::new();

    // 1. Signature Count (Compact-u16: 1 byte for values < 128)
    packet.push(1);

    // 2. Signature (64 bytes of 0xAA)
    packet.extend_from_slice(&[0xAA; 64]);

    // 3. Message Header (3 bytes)
    packet.push(1); // num_required_signatures
    packet.push(0); // num_readonly_signed
    packet.push(1); // num_readonly_unsigned

    // 4. Accounts (Count: 2)
    packet.push(2);
    packet.extend_from_slice(&[0xBB; 32]); // Account 1
    packet.extend_from_slice(&[0xCC; 32]); // Account 2

    // 5. Blockhash (32 bytes)
    packet.extend_from_slice(&[0xDD; 32]);

    loop {
        socket.send_to(&packet, target).unwrap();
        println!("Sent packet");
        thread::sleep(Duration::from_secs(1));
    }
}
