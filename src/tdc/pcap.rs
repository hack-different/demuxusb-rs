//! Export of .tdc packets to pcapng, using the link-layer USB 2.0 link types that Wireshark's
//! `usbll` dissector understands (LINKTYPE_USB_2_0 and its per-speed variants, 288 and 293-295).
//! Each packet is written exactly as captured: PID, payload and CRC.

use super::{Speed, TdcError, TdcFile};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;
use std::borrow::Cow;
use std::io::Write;

/// Interfaces in the order they are written; the index is the pcapng interface id.
const INTERFACES: [DataLink; 4] = [
    DataLink::USB_2_0,
    DataLink::USB_2_0_LOW_SPEED,
    DataLink::USB_2_0_FULL_SPEED,
    DataLink::USB_2_0_HIGH_SPEED,
];

fn interface_for(speed: Option<Speed>) -> u32 {
    match speed {
        Some(Speed::Low) => 1,
        Some(Speed::Full) => 2,
        Some(Speed::High) => 3,
        _ => 0,
    }
}

/// Writes every packet record (optionally only those of one capture) and returns how many were written.
pub fn write_pcapng<W: Write>(
    file: &TdcFile,
    capture: Option<u8>,
    output: W,
) -> Result<usize, TdcError> {
    let to_io = |err: pcap_file::PcapError| TdcError::Io(std::io::Error::other(err));

    let mut writer = PcapNgWriter::new(output).map_err(to_io)?;
    for linktype in INTERFACES {
        writer
            .write_pcapng_block(InterfaceDescriptionBlock {
                linktype,
                snaplen: 0xffff,
                // Nanosecond timestamps: the analyzer clock is 60 MHz.
                options: vec![InterfaceDescriptionOption::IfTsResol(9)],
            })
            .map_err(to_io)?;
    }

    let mut written = 0;
    for record in file.records() {
        let record = record?;
        if capture.is_some_and(|id| id != record.capture) {
            continue;
        }
        let Some(data) = record.packet_data() else {
            continue;
        };
        let Some(session) = file.capture(record.capture) else {
            return Err(TdcError::Corrupt {
                offset: record.offset,
                reason: format!(
                    "record refers to capture {} which is not in the capture table",
                    record.capture
                ),
            });
        };

        writer
            .write_pcapng_block(EnhancedPacketBlock {
                interface_id: interface_for(record.status().map(|s| s.speed)),
                timestamp: session.absolute_time(record.timestamp),
                original_len: data.len() as u32,
                data: Cow::Borrowed(data),
                options: vec![],
            })
            .map_err(to_io)?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_file::pcapng::{Block, PcapNgReader};

    #[test]
    fn exports_synthetic_packets() {
        let mut stream = vec![0x05, 1, 0, 0, 0, 3, 0, 0, 0];
        stream.extend_from_slice(&100u32.to_le_bytes());
        stream.extend_from_slice(&101u32.to_le_bytes());
        stream.extend_from_slice(&60_000_000u64.to_le_bytes());
        stream.extend_from_slice(&60_000_000u32.to_le_bytes());
        stream.extend_from_slice(&[0; 16]);
        stream.extend(
            hex::decode(
                "00410000000000000100000014000000010000d23019000000002d00000000030a00000003000000\
             03030a00000002ff00000b030f0000000000000001000000d2",
            )
            .unwrap(),
        );
        let file = TdcFile::parse(&crate::tdc::tests::build_file(&stream)).unwrap();

        let mut out = Vec::new();
        assert_eq!(write_pcapng(&file, None, &mut out).unwrap(), 1);
        assert_eq!(write_pcapng(&file, Some(2), &mut Vec::new()).unwrap(), 0);

        let mut reader = PcapNgReader::new(out.as_slice()).unwrap();
        let mut packets = Vec::new();
        while let Some(block) = reader.next_block() {
            if let Block::EnhancedPacket(epb) = block.unwrap() {
                packets.push(epb.into_owned());
            }
        }
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].interface_id, 2);
        assert_eq!(packets[0].data.as_ref(), &[0xd2]);
        assert_eq!(
            packets[0].timestamp,
            file.captures[0].absolute_time(0x1930d200)
        );
    }
}
