//! The Beagle USB 480 capture stream (bulk EP 0x82), as read by `bg480_read_hw_record`
//! (0x1979c in `beagle.so`).
//!
//! The stream is a run of records. Each starts with a little-endian u16 header whose top two bits
//! give the record type, and the type gives the base length:
//!
//! | Type | Length | Contents |
//! |---|---|---|
//! | 0 | 2 | control: bits 10-12 subtype, bit 13 timestamp wrap |
//! | 1 | 6 + n | packet: bits 0-10 byte count, bit 11 truncated, bit 12 bad signals; u16 timestamp, bytes (padded to even), u16 end timestamp |
//! | 2 | 4 | event: u16 timestamp |
//! | 3 | 6 | extended: u16 and u32 fields |
//!
//! Records only carry the low 16 bits of the 60 MHz timestamp. [`Parser`] keeps the high bits
//! the same way the library does.

use crate::tdc::ReadStatus;

/// Base record length by type, `bg480_hw_record_len_by_type` (0x4f39c).
const RECORD_LEN: [usize; 4] = [2, 6, 4, 6];

const TYPE_SHIFT: u32 = 14;
const PACKET_LEN_MASK: u16 = 0x07ff;
const PACKET_TRUNCATED: u16 = 0x0800;
const PACKET_BAD_SIGNALS: u16 = 0x1000;
const TIMESTAMP_WRAP: u16 = 0x2000;
const EXTENDED_HAS_TIMESTAMP: u16 = 0x1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwRecord {
    /// Type 0. `subtype` is bits 10-12: 0 with an all-zero header ends the capture, 1 is an idle
    /// tick, 2 says a timestamp record follows, 3 carries speed and port data (USB 5000 only).
    Control { header: u16, subtype: u8 },
    /// Type 1, one USB packet as seen on the wire (PID, payload, CRC).
    Packet {
        header: u16,
        data: Vec<u8>,
        /// Low 16 bits of the end timestamp.
        end_time: u16,
    },
    /// Type 2.
    Event { header: u16 },
    /// Type 3: a u16 then a u32. When bits 12-13 of the header are 0x1000 the u16 is the
    /// timestamp; otherwise the library sets the low timestamp bits to zero.
    Extended { header: u16, first: u16, second: u32 },
}

impl HwRecord {
    pub fn header(&self) -> u16 {
        match self {
            HwRecord::Control { header, .. }
            | HwRecord::Packet { header, .. }
            | HwRecord::Event { header }
            | HwRecord::Extended { header, .. } => *header,
        }
    }

    /// True for the all-zero control record that ends a capture.
    pub fn is_end_of_capture(&self) -> bool {
        matches!(self, HwRecord::Control { header: 0, .. })
    }

    /// For packets: the API read status the library derives from the record alone (it also adds
    /// bits that depend on bus state, such as timeouts).
    pub fn packet_status(&self) -> Option<ReadStatus> {
        let HwRecord::Packet { header, data, .. } = self else { return None };
        let mut status = 0;
        if header & PACKET_TRUNCATED != 0 {
            status |= ReadStatus::USB_TRUNCATION_MODE;
        }
        if header & PACKET_BAD_SIGNALS != 0 {
            status |= ReadStatus::USB_ERR_BAD_SIGNALS;
        }
        if let Some(&pid) = data.first() {
            if pid >> 4 != !pid & 0x0f {
                status |= ReadStatus::USB_ERR_BAD_PID;
            }
        }
        if crc_is_bad(data) {
            status |= ReadStatus::USB_ERR_BAD_CRC;
        }
        Some(ReadStatus(status))
    }
}

/// A record and its full timestamp in 60 MHz ticks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timed {
    pub time: u64,
    pub record: HwRecord,
}

/// Splits stream bytes into records. Feed it bytes as they arrive from EP 0x82.
#[derive(Debug, Default)]
pub struct Parser {
    pending: Vec<u8>,
    time: u64,
}

impl Parser {
    pub fn new() -> Parser {
        Parser::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    /// The next complete record, or `None` until more bytes are pushed.
    pub fn next_record(&mut self) -> Option<Timed> {
        let header = u16::from_le_bytes([*self.pending.first()?, *self.pending.get(1)?]);
        let kind = (header >> TYPE_SHIFT) as usize;
        let mut len = RECORD_LEN[kind];
        let mut data_len = 0;
        if kind == 1 {
            data_len = (header & PACKET_LEN_MASK) as usize;
            // The library caps truncated packets at four bytes (0x19858).
            if data_len > 4 && header & PACKET_TRUNCATED != 0 {
                data_len = 4;
            }
            len += (data_len + 1) & !1;
        }
        if self.pending.len() < len {
            return None;
        }
        let bytes: Vec<u8> = self.pending.drain(..len).collect();
        let u16_at = |i: usize| u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let u32_at = |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);

        let (low, record) = match kind {
            0 => {
                let low = if header & TIMESTAMP_WRAP != 0 { 0 } else { self.time as u16 };
                let subtype = ((header >> 10) & 7) as u8;
                (low, HwRecord::Control { header, subtype })
            }
            1 => (
                u16_at(2),
                HwRecord::Packet { header, data: bytes[4..4 + data_len].to_vec(), end_time: u16_at(len - 2) },
            ),
            2 => (u16_at(2), HwRecord::Event { header }),
            _ => {
                let low = if header & 0x3000 == EXTENDED_HAS_TIMESTAMP { u16_at(2) } else { 0 };
                (low, HwRecord::Extended { header, first: u16_at(2), second: u32_at(4) })
            }
        };

        // Bit 13 bumps the high part of the timestamp, except on type-3 records without one.
        let skip_wrap = kind == 3 && header & 0x3000 != EXTENDED_HAS_TIMESTAMP;
        let mut high = self.time & !0xffff;
        if header & TIMESTAMP_WRAP != 0 && !skip_wrap {
            high += 0x10000;
        }
        self.time = high | low as u64;
        Some(Timed { time: self.time, record })
    }
}

impl Iterator for Parser {
    type Item = Timed;

    fn next(&mut self) -> Option<Timed> {
        self.next_record()
    }
}

/// `usb_packet_crc_is_bad` (0x29bdc): CRC5 on 3-byte tokens and 4-byte SPLIT tokens, CRC16 on
/// data packets and anything 4 bytes or longer, nothing on shorter packets.
pub fn crc_is_bad(packet: &[u8]) -> bool {
    match packet.len() {
        0..=2 => false,
        3 => {
            let field = u16::from_le_bytes([packet[1], packet[2]]);
            let crc5_bad = crc5(field as u32 & 0x07ff, 11) != (field >> 11) as u32;
            if packet[0] & 0x33 != 0x03 {
                return crc5_bad;
            }
            // A data PID with no payload, whose CRC16 is 0. The library also accepts a DATA0
            // that reads as a valid token with byte 1 low nibble 1.
            let token_like = packet[0] == 0xc3 && packet[1] & 0x0f == 1 && !crc5_bad;
            !token_like && field != 0
        }
        4 if packet[0] == 0x78 => {
            let field = u32::from_le_bytes([packet[1], packet[2], packet[3], 0]);
            crc5(field & 0x7ffff, 19) != field >> 19
        }
        n => {
            let body = &packet[1..n - 2];
            let sent = u16::from_le_bytes([packet[n - 2], packet[n - 1]]);
            crc16(body) != sent
        }
    }
}

/// USB CRC5 over the low `bits` bits of `value`, LSB first, as stored on the wire.
fn crc5(value: u32, bits: u32) -> u32 {
    let mut crc = 0x1f;
    for i in 0..bits {
        let bit = (value >> i) & 1;
        let top = crc & 1;
        crc >>= 1;
        if bit ^ top != 0 {
            crc ^= 0x14;
        }
    }
    !crc & 0x1f
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xa001 } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet_record(time: u16, bytes: &[u8], end: u16) -> Vec<u8> {
        let mut out = (0x4000u16 | bytes.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&time.to_le_bytes());
        out.extend_from_slice(bytes);
        if bytes.len() % 2 == 1 {
            out.push(0);
        }
        out.extend_from_slice(&end.to_le_bytes());
        out
    }

    #[test]
    fn crc_checks_match_known_packets() {
        // SOF frame 1340 and an IN token to address 0x41 endpoint 1 from the iogear capture.
        assert!(!crc_is_bad(&[0xa5, 0x3c, 0xbd]));
        assert!(crc_is_bad(&[0xa5, 0x3c, 0xbe]));
        // DATA1 with a valid CRC16 from the same capture.
        let data1 = [0x4b, 0x09, 0x29, 0x03, 0x04, 0x00, 0x32, 0x64, 0x0e, 0x3c, 0x64];
        assert!(!crc_is_bad(&data1));
        // A four-byte SOF is checked as CRC16 and fails, as in 20140821_hub.
        assert!(crc_is_bad(&[0xa5, 0xbc, 0x80, 0xf6]));
        // Packets under three bytes are not checked.
        assert!(!crc_is_bad(&[0xa5, 0x9f]));
    }

    #[test]
    fn parses_records_across_pushes() {
        let mut bytes = packet_record(0x1234, &[0xa5, 0x3c, 0xbd], 0x1240);
        bytes.extend_from_slice(&0x8000u16.to_le_bytes()); // event
        bytes.extend_from_slice(&0x1250u16.to_le_bytes());
        bytes.extend_from_slice(&0x2000u16.to_le_bytes()); // control with timestamp wrap
        bytes.extend_from_slice(&0x0000u16.to_le_bytes()); // end of capture

        let mut parser = Parser::new();
        parser.push(&bytes[..5]);
        assert_eq!(parser.next_record(), None);
        parser.push(&bytes[5..]);
        let records: Vec<Timed> = parser.collect();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].time, 0x1234);
        assert_eq!(
            records[0].record,
            HwRecord::Packet { header: 0x4003, data: vec![0xa5, 0x3c, 0xbd], end_time: 0x1240 }
        );
        assert_eq!(records[0].record.packet_status(), Some(ReadStatus(0)));
        assert_eq!(records[1].time, 0x1250);
        assert_eq!(records[2].time, 0x10000);
        assert!(records[3].record.is_end_of_capture());
        assert_eq!(records[3].time, 0x10000);
    }

    #[test]
    fn flags_bad_packets() {
        let mut bytes = packet_record(0, &[0xd5], 0);
        bytes[1] |= (PACKET_BAD_SIGNALS >> 8) as u8;
        let mut parser = Parser::new();
        parser.push(&bytes);
        let status = parser.next_record().unwrap().record.packet_status().unwrap();
        assert_eq!(status.0, ReadStatus::USB_ERR_BAD_SIGNALS | ReadStatus::USB_ERR_BAD_PID);
    }
}
