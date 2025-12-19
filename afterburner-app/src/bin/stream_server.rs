use std::net::SocketAddr;
use std::panic;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

#[tokio::main]
async fn main() {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("new");
    config.set_application_protos(&[b"solana-tpu"]).expect("set_application_protos");
    config.load_cert_chain_from_pem_file("cert.crt").expect("load_cert_chain_from_pem_file");
    config.load_priv_key_from_pem_file("cert.key").expect("load_priv_key_from_pem_file");
    
    config.set_initial_max_data(100_000_000);
    config.set_initial_max_stream_data_bidi_local(10_000_000);
    config.set_initial_max_stream_data_bidi_remote(10_000_000);
    config.set_initial_max_stream_data_uni(10_000_000);
    config.set_initial_max_streams_bidi(1000);
    config.set_initial_max_streams_uni(1000);
    config.set_max_ack_delay(0); 
    config.set_ack_delay_exponent(0);

    let socket = std::net::UdpSocket::bind("10.0.0.11:8004").expect("bind");
    socket.set_nonblocking(true).expect("set_nonblocking");
    println!("[SERVER] Listening on 10.0.0.11:8004");

    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    let mut rx_buf = [0u8; 65535];
    let mut conn: Option<std::pin::Pin<Box<quiche::Connection>>> = None;
    let mut client_addr: Option<SocketAddr> = None;
    
    let mut last_send = std::time::Instant::now();
    let packet_interval = Duration::from_micros(10);
    let mut seq: u64 = 0;
    let mut total_rx_bytes: u64 = 0;

    loop {
        let read_result = socket.recv_from(&mut buf);
        match read_result {
            Ok((len, src)) => {
                client_addr = Some(src);
                let recv_info = quiche::RecvInfo { from: src, to: socket.local_addr().expect("local_addr") };
                
                if conn.is_none() {
                     println!("[SERVER] Client connected from {}", src);
                     if let Ok(hdr) = quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                        let scid = quiche::ConnectionId::from_ref(&hdr.scid);
                        let c = quiche::accept(&scid, None, socket.local_addr().expect("local_addr"), src, &mut config).expect("accept");
                        conn = Some(Box::pin(c));
                    }
                }

                if let Some(c) = &mut conn {
                    c.recv(&mut buf[..len], recv_info).ok();
                    while let Ok((write_len, _)) = c.send(&mut out) {
                        socket.send_to(&out[..write_len], src).ok();
                    }
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(c) = &mut conn {
                    c.on_timeout();
                    
                    if let Some(target) = client_addr {
                        if c.is_established() && last_send.elapsed() >= packet_interval {
                            let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).expect("duration_since").as_nanos() as u64;
                            
                            let mut payload = [0u8; 17];
                            payload[0] = 0xA5; 
                            payload[1..9].copy_from_slice(&now_ns.to_le_bytes());
                            payload[9..17].copy_from_slice(&seq.to_le_bytes());

                            match c.stream_send(1, &payload, false) {
                                Ok(_) => {
                                    seq += 1;
                                    last_send = std::time::Instant::now();
                                    if seq.is_multiple_of(50_000) {
                                        println!("[STATS] Sent: {} | RX: ~{}", seq, total_rx_bytes / 235);
                                    }
                                },
                                Err(quiche::Error::Done) => {}, 
                                Err(_) => {},
                            }
                        }
                        
                        for stream_id in c.readable() {
                            while let Ok((read_len, _fin)) = c.stream_recv(stream_id, &mut rx_buf) {
                                if read_len > 0 {
                                    total_rx_bytes += read_len as u64;
                                }
                            }
                        }
                        
                        while let Ok((write_len, _)) = c.send(&mut out) {
                            socket.send_to(&out[..write_len], target).ok();
                        }
                    }
                }
                std::hint::spin_loop();
            },
            Err(e) => {
                panic::panic_any(e)
            }
        }
    }
}