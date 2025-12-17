pub fn write_headers(frame: &mut [u8], payload_len: usize, src_port: u16, dst_port: u16) {
    // ---------------------------------------------------------
    // 1. ETHERNET HEADER (14 Bytes)
    // ---------------------------------------------------------
    // Dest MAC: FF:FF:FF:FF:FF:FF (Broadcast - guarantees acceptance on veth)
    frame[0] = 0xFF; frame[1] = 0xFF; frame[2] = 0xFF;
    frame[3] = 0xFF; frame[4] = 0xFF; frame[5] = 0xFF;

    // Src MAC: 02:00:00:00:00:01 (Arbitrary Local)
    frame[6] = 0x02; frame[7] = 0x00; frame[8] = 0x00;
    frame[9] = 0x00; frame[10] = 0x00; frame[11] = 0x01;

    // EtherType: IPv4 (0x0800)
    frame[12] = 0x08; frame[13] = 0x00;

    // ---------------------------------------------------------
    // 2. IP HEADER (20 Bytes)
    // ---------------------------------------------------------
    let total_len = (20 + 8 + payload_len) as u16;

    frame[14] = 0x45; // Version 4, Header Len 5
    frame[15] = 0x00; // DSCP/ECN
    frame[16] = (total_len >> 8) as u8;
    frame[17] = (total_len & 0xFF) as u8;
    
    frame[18] = 0x00; frame[19] = 0x00; // ID
    frame[20] = 0x40; frame[21] = 0x00; // Flags (Don't Fragment)
    
    frame[22] = 64;   // TTL
    frame[23] = 17;   // Protocol (UDP)
    frame[24] = 0x00; frame[25] = 0x00; // Checksum (Placeholder)

    // Src IP: 10.0.0.10
    frame[26] = 10; frame[27] = 0; frame[28] = 0; frame[29] = 10;
    // Dst IP: 10.0.0.11
    frame[30] = 10; frame[31] = 0; frame[32] = 0; frame[33] = 11;

    // Calculate IP Checksum
    let checksum = ipv4_checksum(&frame[14..34]);
    frame[24] = (checksum >> 8) as u8;
    frame[25] = (checksum & 0xFF) as u8;

    // ---------------------------------------------------------
    // 3. UDP HEADER (8 Bytes)
    // ---------------------------------------------------------
    let udp_len = (8 + payload_len) as u16;

    frame[34] = (src_port >> 8) as u8;
    frame[35] = (src_port & 0xFF) as u8;
    frame[36] = (dst_port >> 8) as u8;
    frame[37] = (dst_port & 0xFF) as u8;
    frame[38] = (udp_len >> 8) as u8;
    frame[39] = (udp_len & 0xFF) as u8;
    frame[40] = 0x00; frame[41] = 0x00; // UDP Checksum (Optional for IPv4)
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = ((header[i] as u32) << 8) + (header[i+1] as u32);
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}