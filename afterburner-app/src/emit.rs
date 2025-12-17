pub struct MockTransaction {
    pub signature: [u8; 64],
    pub message: [u8; 170],
}

impl MockTransaction {
    pub fn new() -> Self {
        MockTransaction {
            signature: [0xAA; 64],
            message: [0xBB; 170],
        }
    }

    /// Serialize to wire format: [Flag(1)] [Signature(64)] [Message(170)] = 235 bytes
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = 0x00;
        buf[1..65].copy_from_slice(&self.signature);
        buf[65..235].copy_from_slice(&self.message);
        235
    }
}
