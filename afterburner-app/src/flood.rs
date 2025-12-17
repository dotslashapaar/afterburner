use crate::quic_driver::QuicDriver;
use crate::emit::MockTransaction;

pub struct Flooder {
    pub tx_count: u64,
    batch_size: usize,
    mock_tx: MockTransaction,
    buf: [u8; 1024],
}

impl Flooder {
    pub fn new() -> Self {
        Flooder {
            tx_count: 0,
            batch_size: 4,
            mock_tx: MockTransaction::new(),
            buf: [0u8; 1024],
        }
    }

    pub fn shoot(&mut self, driver: &mut QuicDriver) {
        if !driver.conn.is_established() {
            return;
        }

        let len = self.mock_tx.serialize(&mut self.buf);
        let payload = &self.buf[..len];

        for i in 0..self.batch_size {
            let stream_id = (i * 4) as u64;

            match driver.conn.stream_send(stream_id, payload, false) {
                Ok(written) if written == len => {
                    self.tx_count += 1;
                }
                Ok(_) => {}
                Err(quiche::Error::Done) => break,
                Err(_) => {}
            }
        }
    }
}
