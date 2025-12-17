use std::net::SocketAddr;
use std::pin::Pin;

pub struct QuicDriver {
    pub conn: Pin<Box<quiche::Connection>>,
    stream_buf: [u8; 65535], 
    closed_seen: bool,
    established_seen: bool,
    close_timer: Option<std::time::Instant>,
    msg_buf: Vec<u8>,
    stats_count: u64,
    stats_sum_ns: u64,
    min_lat_ns: u64,
    max_lat_ns: u64,
    last_seq: Option<u64>,
    lost_packets: u64,
    last_stats_time: std::time::Instant,
    total_rx_msgs: u64,
}

impl QuicDriver {
    pub fn new(scid: &[u8], local: SocketAddr, peer: SocketAddr) -> Self {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        
        config.verify_peer(false);
        config.set_application_protos(&[b"solana-tpu"]).unwrap();
        config.set_max_ack_delay(0);
        config.set_ack_delay_exponent(0);
        config.set_disable_active_migration(true);
        config.enable_early_data();
        config.set_initial_max_data(100_000_000);
        config.set_initial_max_stream_data_bidi_local(10_000_000);
        config.set_initial_max_stream_data_bidi_remote(10_000_000);
        config.set_initial_max_stream_data_uni(10_000_000); 
        config.set_initial_max_streams_bidi(1000);
        config.set_initial_max_streams_uni(1000);

        let scid_obj = quiche::ConnectionId::from_ref(scid);
        let conn = quiche::connect(None, &scid_obj, local, peer, &mut config).unwrap();

        QuicDriver {
            conn: Box::pin(conn),
            stream_buf: [0; 65535],
            closed_seen: false,
            established_seen: false,
            close_timer: None,
            msg_buf: Vec::with_capacity(1024),
            stats_count: 0,
            stats_sum_ns: 0,
            min_lat_ns: u64::MAX,
            max_lat_ns: 0,
            last_seq: None,
            lost_packets: 0,
            last_stats_time: std::time::Instant::now(),
            total_rx_msgs: 0,
        }
    }

    pub fn process_input(&mut self, data: &mut [u8], local: SocketAddr, peer: SocketAddr) {
        let recv_info = quiche::RecvInfo { from: peer, to: local };
        if self.conn.recv(data, recv_info).is_ok()
            && self.conn.is_established()
            && !self.established_seen
        {
            println!("[QUIC] Connection established");
            self.established_seen = true;
        }
    }

    pub fn write_transmit(&mut self, frame: &mut [u8]) -> Option<usize> {
        match self.conn.send(frame) {
            Ok((written, _)) => Some(written),
            Err(_) => None, 
        }
    }

    pub fn drain_streams(&mut self) {
        if self.conn.is_established() {
            // Only process stream 1 (server-initiated unidirectional for timestamps)
            while let Ok((read_len, _fin)) = self.conn.stream_recv(1, &mut self.stream_buf) {
                if read_len == 0 { break; }
                
                // Append new data to message buffer
                self.msg_buf.extend_from_slice(&self.stream_buf[..read_len]);
            }
            
            // Process complete 17-byte messages
            while self.msg_buf.len() >= 17 {
                // Find magic byte
                if self.msg_buf[0] != 0xA5 {
                    // Discard byte and resync
                    self.msg_buf.remove(0);
                    continue;
                }
                
                // Extract complete message
                let ts_bytes: [u8; 8] = self.msg_buf[1..9].try_into().unwrap();
                let server_ts = u64::from_le_bytes(ts_bytes);
                
                let seq_bytes: [u8; 8] = self.msg_buf[9..17].try_into().unwrap();
                let seq = u64::from_le_bytes(seq_bytes);
                
                // Remove processed message
                self.msg_buf.drain(..17);
                
                // Loss Detection
                if let Some(last) = self.last_seq {
                    if seq > last + 1 {
                        let gap = seq - last - 1;
                        self.lost_packets += gap;
                    }
                }
                self.last_seq = Some(seq);
                
                // Latency Calculation
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                
                let latency_ns = now_ns.saturating_sub(server_ts);
                
                if latency_ns < self.min_lat_ns { self.min_lat_ns = latency_ns; }
                if latency_ns > self.max_lat_ns { self.max_lat_ns = latency_ns; }
                
                self.stats_count += 1;
                self.stats_sum_ns += latency_ns;
                self.total_rx_msgs += 1;
                
                if self.last_stats_time.elapsed() >= std::time::Duration::from_millis(500) && self.stats_count > 0 {
                    let avg_lat_us = (self.stats_sum_ns as f64 / self.stats_count as f64) / 1000.0;
                    let min_lat_us = self.min_lat_ns as f64 / 1000.0;
                    let max_lat_us = self.max_lat_ns as f64 / 1000.0;
                    
                    println!("[STATS] Lat(us) Avg={:.1} Min={:.1} Max={:.1} | RX: {} | Lost: {}", 
                        avg_lat_us, min_lat_us, max_lat_us,
                        self.total_rx_msgs,
                        self.lost_packets
                    );
                    
                    self.stats_count = 0;
                    self.stats_sum_ns = 0;
                    self.min_lat_ns = u64::MAX;
                    self.max_lat_ns = 0;
                    self.last_stats_time = std::time::Instant::now();
                }
            }
            
            for stream_id in self.conn.readable() {
                if stream_id == 1 { continue; }
                while let Ok((read_len, _fin)) = self.conn.stream_recv(stream_id, &mut self.stream_buf) {
                    if read_len == 0 { break; }
                }
            }
        }
        
        if self.conn.is_closed() && !self.closed_seen {
            self.closed_seen = true;
            if let Some(err) = self.conn.peer_error() {
                println!("[CLOSE] Peer: is_app={} code={} reason={:?}", 
                    err.is_app, err.error_code, String::from_utf8_lossy(&err.reason));
            } else if let Some(err) = self.conn.local_error() {
                println!("[CLOSE] Local: is_app={} code={} reason={:?}", 
                    err.is_app, err.error_code, String::from_utf8_lossy(&err.reason));
            } else if self.conn.is_timed_out() {
                println!("[CLOSE] Timed out");
            } else {
                println!("[CLOSE] Unknown reason");
            }
            self.close_timer = Some(std::time::Instant::now());
        }
    }

    pub fn on_timeout(&mut self) {
        self.conn.on_timeout();
    }
}