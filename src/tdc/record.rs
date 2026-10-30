//! Records and their tagged elements, as found in the decompressed .tdc stream.
//!
//! Every record has the same fixed prefix followed by a list of elements. Each element is
//! `tag: u8, kind: u8 (always 3), length: u32 (including these 6 bytes), payload`. The element
//! tags a file uses are listed in its header (see [`super::ElementType`]).

use super::TdcError;
use std::fmt;

/// Size of the record header plus the fixed fields before the first element.
pub const RECORD_FIXED_LEN: usize = 30;
/// Size of an element's `tag, kind, length` prefix.
pub const ELEMENT_HEADER_LEN: usize = 6;

/// Bus speed from the low bits of the status element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Unknown,
    Low,
    Full,
    /// The Beagle API uses the same codes internally (1 low, 3 full, 4 high), see
    /// `docs/tdc-format.md`. None of the reference captures with a CSV export are high-speed.
    High,
    Other(u8),
}

impl Speed {
    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Speed::Unknown,
            1 => Speed::Low,
            3 => Speed::Full,
            4 => Speed::High,
            other => Speed::Other(other),
        }
    }
}

impl fmt::Display for Speed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Speed::Unknown => write!(f, ""),
            Speed::Low => write!(f, "LS"),
            Speed::Full => write!(f, "FS"),
            Speed::High => write!(f, "HS"),
            Speed::Other(bits) => write!(f, "?{bits}"),
        }
    }
}

/// Element 0x00, present on every record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub raw: u8,
    pub speed: Speed,
    /// Bit 0x20. Matches the "Err" column of Data Center's CSV export.
    pub error: bool,
    pub reserved: u8,
    /// Index into the device table in the file footer, `None` when the record has no device.
    pub device_index: Option<u16>,
}

/// Element 0x03, describing a packet or a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketInfo {
    /// On a packet, the low four bits of the USB PID (e.g. 0xD SETUP, 0x9 IN, 0x3 DATA0, 0x2 ACK).
    /// On a transaction the meaning is not established (0x00, 0x01 and 0x02 are common).
    pub pid: u8,
    /// 0xFF on a single packet, 0x01 on a transaction. Other values are not yet understood.
    pub kind: u8,
    pub address: u8,
    pub endpoint: u8,
    /// Bit 4 of the endpoint byte: set for IN traffic.
    pub direction_in: bool,
}

/// The Beagle API's per-read status word (`BG_READ_*` / `BG_READ_USB_*` in `beagle.h`), which
/// Data Center stores unchanged on packets (element 0x0B) and bus events (element 0x0F).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReadStatus(pub u32);

impl ReadStatus {
    pub const TIMEOUT: u32 = 0x0000_0100;
    pub const ERR_MIDDLE_OF_PACKET: u32 = 0x0000_0200;
    pub const ERR_SHORT_BUFFER: u32 = 0x0000_0400;
    pub const ERR_PARTIAL_LAST_BYTE: u32 = 0x0000_0800;
    pub const ERR_UNEXPECTED: u32 = 0x0000_1000;
    pub const USB_ERR_BAD_SIGNALS: u32 = 0x0001_0000;
    pub const USB_ERR_BAD_SYNC: u32 = 0x0002_0000;
    pub const USB_ERR_BIT_STUFF: u32 = 0x0004_0000;
    pub const USB_ERR_FALSE_EOP: u32 = 0x0008_0000;
    pub const USB_ERR_LONG_EOP: u32 = 0x0010_0000;
    pub const USB_ERR_BAD_PID: u32 = 0x0020_0000;
    pub const USB_ERR_BAD_CRC: u32 = 0x0040_0000;
    pub const USB_TRUNCATION_MODE: u32 = 0x2000_0000;
    pub const USB_END_OF_CAPTURE: u32 = 0x4000_0000;

    /// Names of the USB 1.x/2.0 bits, in bit order. Data Center's CSV `Err` column shows
    /// `TIMEOUT` as "T" and `ERR_UNEXPECTED` as "U".
    pub const NAMES: [(u32, &'static str); 14] = [
        (Self::TIMEOUT, "TIMEOUT"),
        (Self::ERR_MIDDLE_OF_PACKET, "MIDDLE_OF_PACKET"),
        (Self::ERR_SHORT_BUFFER, "SHORT_BUFFER"),
        (Self::ERR_PARTIAL_LAST_BYTE, "PARTIAL_LAST_BYTE"),
        (Self::ERR_UNEXPECTED, "UNEXPECTED"),
        (Self::USB_ERR_BAD_SIGNALS, "BAD_SIGNALS"),
        (Self::USB_ERR_BAD_SYNC, "BAD_SYNC"),
        (Self::USB_ERR_BIT_STUFF, "BIT_STUFF"),
        (Self::USB_ERR_FALSE_EOP, "FALSE_EOP"),
        (Self::USB_ERR_LONG_EOP, "LONG_EOP"),
        (Self::USB_ERR_BAD_PID, "BAD_PID"),
        (Self::USB_ERR_BAD_CRC, "BAD_CRC"),
        (Self::USB_TRUNCATION_MODE, "TRUNCATION_MODE"),
        (Self::USB_END_OF_CAPTURE, "END_OF_CAPTURE"),
    ];

    pub fn contains(self, bits: u32) -> bool {
        self.0 & bits == bits
    }

    /// Bits not covered by [`ReadStatus::NAMES`], ignoring the truncation length in bits 0-7.
    pub fn unknown_bits(self) -> u32 {
        let known = Self::NAMES.iter().fold(0xff, |acc, (bit, _)| acc | bit);
        self.0 & !known
    }
}

impl fmt::Display for ReadStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = Self::NAMES
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, name)| *name)
            .collect();
        match (names.is_empty(), self.unknown_bits()) {
            (true, 0) => write!(f, "OK"),
            (_, 0) => write!(f, "{}", names.join("|")),
            (_, rest) => write!(f, "{}{}{rest:#x}", names.join("|"), if names.is_empty() { "" } else { "|" }),
        }
    }
}

/// Bus event codes (element 0x0F) checked against Data Center's CSV exports. Each code is one
/// CSV row; some rows list several line states.
pub fn bus_event_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "Reset / Keep-alive / Target disconnected",
        0x01 => "Reset / Target disconnected",
        0x04 => "Reset / Chirp J / Tiny J",
        0x07 => "Host disconnected",
        0x08 => "Host connected",
        0x0a => "Low-speed",
        0x0b => "Full-speed",
        0x0e => "Suspend",
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Element {
    /// 0x00
    Status(Status),
    /// 0x01, an empty element on the record that opens a capture.
    CaptureStarted,
    /// 0x02, an empty element on bus-level records (SOF groups, bus events).
    BusRecord,
    /// 0x03
    PacketInfo(PacketInfo),
    /// 0x04, the address and endpoint of a collapsed group such as `[6 IN-NAK]`.
    GroupInfo {
        raw: [u8; 2],
        address: u8,
        endpoint: u8,
        direction_in: bool,
    },
    /// 0x05, the number of packets a group collapses.
    GroupCount { count: u32, reserved: u16 },
    /// 0x06, a run of start-of-frame packets. `flags` is 0x10 on SOF runs and 0x11 on low-speed
    /// keep-alive runs (whose frame numbers do not span `count`).
    SofGroup {
        count: u32,
        reserved: u8,
        flags: u8,
        first_frame: u16,
        last_frame: u16,
    },
    /// 0x0B, the raw bytes of one USB packet: PID, payload and CRC, without SYNC or EOP, and the
    /// Beagle API read status for it.
    Packet { status: ReadStatus, data: Vec<u8> },
    /// 0x0C, a transaction made of child records (listed newest first).
    Transaction { kind: u8, children: Vec<u32> },
    /// 0x0F, a bus state change: a Data Center event code (see [`bus_event_name`]; these are not
    /// the API's `BG_EVENT_USB_*` bits) and the Beagle API read status for it.
    BusEvent { code: u8, status: ReadStatus },
    /// 0x14 and 0x16: a count followed by child record numbers.
    ChildList {
        tag: u8,
        count: u32,
        children: Vec<u32>,
    },
    /// 0x15, a user comment stored as UTF-16LE.
    Comment(String),
    /// An element with an empty payload whose meaning is not known (0x08, 0x09, 0x12, 0x13, 0x17).
    Flag(u8),
    /// Anything else, kept verbatim.
    Unknown { tag: u8, data: Vec<u8> },
}

impl Element {
    pub fn tag(&self) -> u8 {
        match self {
            Element::Status(_) => 0x00,
            Element::CaptureStarted => 0x01,
            Element::BusRecord => 0x02,
            Element::PacketInfo(_) => 0x03,
            Element::GroupInfo { .. } => 0x04,
            Element::GroupCount { .. } => 0x05,
            Element::SofGroup { .. } => 0x06,
            Element::Packet { .. } => 0x0b,
            Element::Transaction { .. } => 0x0c,
            Element::BusEvent { .. } => 0x0f,
            Element::ChildList { tag, .. } => *tag,
            Element::Comment(_) => 0x15,
            Element::Flag(tag) => *tag,
            Element::Unknown { tag, .. } => *tag,
        }
    }

    pub(crate) fn decode(tag: u8, data: &[u8]) -> Element {
        let u16_at = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
        let u32_at =
            |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let u32_list = |from: usize| {
            data[from..]
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        };

        match (tag, data.len()) {
            (0x00, 4) => {
                let device = u16_at(2);
                Element::Status(Status {
                    raw: data[0],
                    speed: Speed::from_bits(data[0] & 0x07),
                    error: data[0] & 0x20 != 0,
                    reserved: data[1],
                    device_index: if device == 0xffff { None } else { Some(device) },
                })
            }
            (0x01, 0) => Element::CaptureStarted,
            (0x02, 0) => Element::BusRecord,
            (0x03, 4) => Element::PacketInfo(PacketInfo {
                pid: data[0],
                kind: data[1],
                address: data[2],
                endpoint: data[3] & 0x0f,
                direction_in: data[3] & 0x10 != 0,
            }),
            (0x04, 4) => Element::GroupInfo {
                raw: [data[0], data[1]],
                address: data[2],
                endpoint: data[3] & 0x0f,
                direction_in: data[3] & 0x10 != 0,
            },
            (0x05, 6) => Element::GroupCount {
                count: u32_at(0),
                reserved: u16_at(4),
            },
            (0x06, 10) => Element::SofGroup {
                count: u32_at(0),
                reserved: data[4],
                flags: data[5],
                first_frame: u16_at(6),
                last_frame: u16_at(8),
            },
            (0x0b, len) if len >= 8 && 8 + u32_at(4) as usize == len => Element::Packet {
                status: ReadStatus(u32_at(0)),
                data: data[8..].to_vec(),
            },
            (0x0c, len) if len >= 2 && len == 2 + 4 * data[1] as usize => Element::Transaction {
                kind: data[0],
                children: u32_list(2),
            },
            (0x0f, 5) => Element::BusEvent {
                code: data[0],
                status: ReadStatus(u32_at(1)),
            },
            (0x14 | 0x16, len) if len >= 4 && len % 4 == 0 => Element::ChildList {
                tag,
                count: u32_at(0),
                children: u32_list(4),
            },
            (0x15, len) if len >= 4 && len == 4 + 2 * u32_at(0) as usize => {
                let units: Vec<u16> = data[4..]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                Element::Comment(String::from_utf16_lossy(&units))
            }
            (0x08 | 0x09 | 0x12 | 0x13 | 0x17, 0) => Element::Flag(tag),
            _ => Element::Unknown {
                tag,
                data: data.to_vec(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Offset of the record in the decompressed stream.
    pub offset: usize,
    /// Record header flags. Bit 0x10 is set on top-level records; the other bits are not understood.
    pub flags: u8,
    /// Sequence number, contiguous from 0 across every capture in the file.
    pub sequence: u32,
    /// True for records that only appear inside another record (e.g. packets of a transaction).
    pub nested: bool,
    /// Always 20 in every sample seen.
    pub reserved: u32,
    /// The capture (1-based, see [`super::Capture::id`]) this record belongs to.
    pub capture: u8,
    pub capture_flags: u8,
    /// Start time in analyzer ticks since the start of the capture.
    pub timestamp: u64,
    /// Duration in analyzer ticks.
    pub duration: u32,
    pub elements: Vec<Element>,
}

impl Record {
    pub(crate) fn parse(stream: &[u8], offset: usize) -> Result<(Record, usize), TdcError> {
        let corrupt = |reason: String| TdcError::Corrupt { offset, reason };
        let fixed = stream
            .get(offset..offset + RECORD_FIXED_LEN)
            .ok_or_else(|| corrupt("record header runs past the end of the stream".into()))?;

        let flags = fixed[0];
        let length = u16::from_le_bytes([fixed[1], fixed[2]]) as usize;
        if fixed[3] != 0 || length < RECORD_FIXED_LEN {
            return Err(corrupt(format!("bad record header {:02x?}", &fixed[..4])));
        }
        let body = stream.get(offset..offset + length).ok_or_else(|| {
            corrupt(format!(
                "record of {length} bytes runs past the end of the stream"
            ))
        })?;

        let u32_at =
            |i: usize| u32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&body[18..26]);

        let mut elements = Vec::new();
        let mut cursor = RECORD_FIXED_LEN;
        while cursor < length {
            let header = body
                .get(cursor..cursor + ELEMENT_HEADER_LEN)
                .ok_or_else(|| {
                    corrupt(format!("element header at +{cursor} runs past the record"))
                })?;
            let tag = header[0];
            let element_len =
                u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
            if header[1] != 3 || element_len < ELEMENT_HEADER_LEN || cursor + element_len > length {
                return Err(corrupt(format!(
                    "bad element header {header:02x?} at +{cursor}"
                )));
            }
            elements.push(Element::decode(
                tag,
                &body[cursor + ELEMENT_HEADER_LEN..cursor + element_len],
            ));
            cursor += element_len;
        }

        let record = Record {
            offset,
            flags,
            sequence: u32_at(4),
            nested: u32_at(8) != 0,
            reserved: u32_at(12),
            capture: body[16],
            capture_flags: body[17],
            timestamp: u64::from_le_bytes(timestamp),
            duration: u32_at(26),
            elements,
        };
        Ok((record, offset + length))
    }

    pub fn status(&self) -> Option<&Status> {
        self.elements.iter().find_map(|e| match e {
            Element::Status(status) => Some(status),
            _ => None,
        })
    }

    pub fn packet_info(&self) -> Option<&PacketInfo> {
        self.elements.iter().find_map(|e| match e {
            Element::PacketInfo(info) => Some(info),
            _ => None,
        })
    }

    /// The raw USB packet bytes, if this record is a single packet.
    pub fn packet_data(&self) -> Option<&[u8]> {
        self.elements.iter().find_map(|e| match e {
            Element::Packet { data, .. } => Some(data.as_slice()),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // An ACK packet record from serial/ftdi/FT230X_Basic_UART_w7_init.tdc in the USBTraces collection.
    const ACK_RECORD: &str =
        "00410000120000000100000014000000020000d23019000000002d00000000030a00000003000000\
                              03030a00000002ff00000b030f0000000000000001000000d2";

    #[test]
    fn parses_packet_record() {
        let bytes = hex::decode(ACK_RECORD).unwrap();
        let (record, next) = Record::parse(&bytes, 0).unwrap();
        assert_eq!(next, bytes.len());
        assert_eq!(record.sequence, 18);
        assert!(record.nested);
        assert_eq!(record.capture, 2);
        assert_eq!(record.timestamp, 0x1930d200);
        assert_eq!(record.duration, 45);
        assert_eq!(record.status().unwrap().speed, Speed::Full);
        let info = record.packet_info().unwrap();
        assert_eq!(
            (info.pid, info.kind, info.address, info.endpoint),
            (0x2, 0xff, 0, 0)
        );
        assert_eq!(record.packet_data(), Some(&[0xd2u8][..]));
    }

    #[test]
    fn rejects_overlong_element() {
        let mut bytes = hex::decode(ACK_RECORD).unwrap();
        let last_element = bytes.len() - 15;
        bytes[last_element + 2] = 0x40;
        assert!(Record::parse(&bytes, 0).is_err());
    }

    #[test]
    fn decodes_transaction_and_comment() {
        let txn = hex::decode("0c03140000001300000012000000").unwrap();
        assert_eq!(
            Element::decode(0x0c, &txn),
            Element::Transaction {
                kind: 0x0c,
                children: vec![20, 19, 18]
            }
        );

        let comment = hex::decode("0200000048006900").unwrap();
        assert_eq!(
            Element::decode(0x15, &comment),
            Element::Comment("Hi".into())
        );
    }
}
