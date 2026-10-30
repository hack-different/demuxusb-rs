//! Native driver for Total Phase Beagle USB protocol analyzers, without the vendor library.
//!
//! Everything here is transcribed from `beagle.so` (Beagle API v6.00), disassembled in Binary
//! Ninja. `docs/beagle-usb-protocol.md` lists the addresses each piece comes from. The analyzer
//! talks over three bulk endpoints:
//!
//! * EP 0x01 OUT / EP 0x81 IN: 64-byte commands and their 64-byte replies ([`Command`]).
//! * EP 0x82 IN: the capture stream, a run of hardware records ([`stream`]).
//!
//! Only the Beagle USB 480 path (device type 0x43) has been traced so far.

pub mod stream;
pub mod usb;

use std::fmt;

/// Total Phase's USB vendor id.
pub const VENDOR_ID: u16 = 0x1679;
/// Product ids the library opens.
pub const PRODUCT_IDS: [u16; 2] = [0x2001, 0x2002];
/// An unprogrammed Cypress FX2 (`04b4:00f3`) that the library also accepts when asked to.
pub const UNPROGRAMMED_ID: (u16, u16) = (0x04b4, 0x00f3);

pub const COMMAND_OUT_EP: u8 = 0x01;
pub const COMMAND_IN_EP: u8 = 0x81;
pub const STREAM_EP: u8 = 0x82;
pub const COMMAND_LEN: usize = 64;

/// Command opcodes, the little-endian u16 at the start of every command packet.
pub mod opcode {
    /// Tell the firmware which analyzer model it is driving (argument from [`super::DeviceType::mode`]).
    pub const SET_MODE: u16 = 0x01;
    /// Argument 1 before a firmware upload, 0 otherwise.
    pub const PREPARE: u16 = 0x03;
    /// Three argument bytes; the library waits 20 ms after it.
    pub const CONFIGURE: u16 = 0x06;
    /// Returns one byte (stored by the library at device offset 0x1e).
    pub const QUERY_0E: u16 = 0x0e;
    /// Register write: register, chunk flags, chunk length, then up to 59 bytes.
    pub const REGISTER_WRITE: u16 = 0x14;
    /// Returns one byte (stored by the library at device offset 0x1f).
    pub const QUERY_15: u16 = 0x15;
    /// Firmware 2.x: announces a register write of 60 bytes or more (u16 length follows).
    pub const LONG_WRITE: u16 = 0x1a;
    /// Firmware 2.x: register read request.
    pub const REGISTER_READ: u16 = 0x1b;
}

/// Most data bytes one command packet can carry after the 5-byte register-write header.
pub const REGISTER_CHUNK: usize = 59;

/// A 64-byte command packet. Replies come back in the same layout.
#[derive(Clone, PartialEq, Eq)]
pub struct Command(pub [u8; COMMAND_LEN]);

impl Command {
    pub fn new(opcode: u16, args: &[u8]) -> Command {
        let mut bytes = [0u8; COMMAND_LEN];
        bytes[..2].copy_from_slice(&opcode.to_le_bytes());
        bytes[2..2 + args.len()].copy_from_slice(args);
        Command(bytes)
    }

    pub fn opcode(&self) -> u16 {
        u16::from_le_bytes([self.0[0], self.0[1]])
    }

    /// The byte right after the opcode, which is where one-byte query results come back.
    pub fn result_byte(&self) -> u8 {
        self.0[2]
    }

    /// The packets the library sends for a register write (`bg_reg_write`, 0xe204).
    ///
    /// Data is split into 59-byte chunks. The flags byte is 3 for a write that fits in one
    /// packet, otherwise 1 on the first chunk, 0 in the middle and 2 on the last. The library
    /// only continues past the first chunk for register 0. Firmware 2.x is sent a
    /// [`opcode::LONG_WRITE`] packet first when the data is 60 bytes or more, and register 0x51
    /// is renamed 0x50.
    pub fn register_write(register: u8, data: &[u8], firmware: FirmwareVersion) -> Vec<Command> {
        let mut register = register;
        let mut packets = Vec::new();
        if firmware.is_v2() {
            if data.len() >= 0x3c {
                let mut long = Command::new(opcode::LONG_WRITE, &[]);
                long.0[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
                packets.push(long);
            }
            if register == 0x51 {
                register = 0x50;
            }
        }
        let chunks: Vec<&[u8]> = data.chunks(REGISTER_CHUNK).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let last = i + 1 == chunks.len();
            let flags = match (i == 0, last) {
                (true, true) => 3,
                (true, false) => 1,
                (false, true) => 2,
                (false, false) => 0,
            };
            let mut packet = Command::new(opcode::REGISTER_WRITE, &[register, flags, chunk.len() as u8]);
            packet.0[5..5 + chunk.len()].copy_from_slice(chunk);
            packets.push(packet);
            if register != 0 {
                break;
            }
        }
        packets
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let used = self.0.iter().rposition(|&b| b != 0).map_or(2, |i| i + 1).max(2);
        write!(f, "Command({:#06x} {:02x?})", self.opcode(), &self.0[2..used])
    }
}

/// Firmware version as the library reports it: the bcdDevice field turned into
/// `major << 8 | minor`, with the minor part in decimal (bcd 0x0213 becomes 2.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirmwareVersion(pub u16);

impl FirmwareVersion {
    pub fn from_bcd(bcd: u16) -> FirmwareVersion {
        let minor = (bcd & 0xf) + ((bcd >> 4) & 0xf) * 10;
        let major = ((bcd >> 8) & 0xf) + (bcd >> 12) * 10;
        FirmwareVersion(major << 8 | minor)
    }

    pub fn major(self) -> u8 {
        (self.0 >> 8) as u8
    }

    pub fn minor(self) -> u8 {
        self.0 as u8
    }

    /// Firmware 2.00 to 2.19, which the library drives without uploading anything.
    pub fn is_v2(self) -> bool {
        (0x200..=0x213).contains(&self.0)
    }

    /// Firmware 1.x, which needs an image uploaded from the host on every open.
    pub fn needs_upload(self) -> bool {
        (0x100..=0x1ff).contains(&self.0)
    }
}

impl fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.major(), self.minor())
    }
}

/// Analyzer model, from the top byte of the unique id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// 0x41: the I2C/SPI/MDIO Beagle.
    Beagle,
    /// 0x42, sampled at 48 MHz.
    Usb12,
    /// 0x43, sampled at 60 MHz.
    Usb480,
    /// 0x44, 0x46 and 0x48. USB 2 traffic is sampled at 60 MHz.
    Usb5000(u8),
    /// 0x51.
    Other51,
    Unknown(u8),
}

impl DeviceType {
    pub fn from_unique_id(unique_id: u32) -> DeviceType {
        match (unique_id >> 24) as u8 {
            0x41 => DeviceType::Beagle,
            0x42 => DeviceType::Usb12,
            0x43 => DeviceType::Usb480,
            id @ (0x44 | 0x46 | 0x48) => DeviceType::Usb5000(id),
            0x51 => DeviceType::Other51,
            id => DeviceType::Unknown(id),
        }
    }

    /// The argument of [`opcode::SET_MODE`] for this model (from 0xd460).
    pub fn mode(self) -> u8 {
        match self {
            DeviceType::Usb12 => 1,
            DeviceType::Usb480 => 2,
            DeviceType::Usb5000(0x44) => 3,
            DeviceType::Usb5000(_) => 4,
            DeviceType::Other51 => 5,
            _ => 0,
        }
    }

    /// Capture clock in kHz, as `bg_samplerate` reports it.
    pub fn sample_rate_khz(self) -> Option<u32> {
        match self {
            DeviceType::Usb12 => Some(48_000),
            DeviceType::Usb480 | DeviceType::Usb5000(_) => Some(60_000),
            _ => None,
        }
    }
}

/// The library's unique id: the decimal digits of the USB serial number string, so
/// `"1124-123456"` is 1124123456.
pub fn unique_id_from_serial(serial: &str) -> u32 {
    serial
        .bytes()
        .filter(u8::is_ascii_digit)
        .fold(0u32, |acc, d| acc.wrapping_mul(10).wrapping_add((d - b'0') as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_version_from_bcd() {
        assert_eq!(FirmwareVersion::from_bcd(0x0213), FirmwareVersion(0x020d));
        assert_eq!(FirmwareVersion::from_bcd(0x0213).to_string(), "2.13");
        assert!(FirmwareVersion::from_bcd(0x0219).is_v2());
        assert!(!FirmwareVersion::from_bcd(0x0220).is_v2());
        assert!(FirmwareVersion::from_bcd(0x0150).needs_upload());
    }

    #[test]
    fn register_write_chunks() {
        let v1 = FirmwareVersion(0x150);
        let single = Command::register_write(0x62, &[0x10], v1);
        assert_eq!(single.len(), 1);
        assert_eq!(&single[0].0[..6], &[0x14, 0x00, 0x62, 3, 1, 0x10]);

        let long = Command::register_write(0, &[0xaa; 130], v1);
        let flags: Vec<u8> = long.iter().map(|c| c.0[3]).collect();
        let lens: Vec<u8> = long.iter().map(|c| c.0[4]).collect();
        assert_eq!(flags, [1, 0, 2]);
        assert_eq!(lens, [59, 59, 12]);

        let v2 = Command::register_write(0x51, &[0; 60], FirmwareVersion(0x20d));
        assert_eq!(v2[0].opcode(), opcode::LONG_WRITE);
        assert_eq!(&v2[0].0[2..4], &[60, 0]);
        assert_eq!(v2[1].0[2], 0x50);
    }

    #[test]
    fn device_type_from_unique_id() {
        assert_eq!(DeviceType::from_unique_id(0x4300_1234), DeviceType::Usb480);
        assert_eq!(unique_id_from_serial("1124-073472"), 1_124_073_472);
        assert_eq!(DeviceType::from_unique_id(1_124_073_472), DeviceType::Usb480);
    }
}
