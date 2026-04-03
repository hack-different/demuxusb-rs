use crate::usb_request_block::{USBControlStage, USBDirection, USBRequestBlock, USBTransferType};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;
use std::borrow::Cow;
use std::fs::File;
use std::io::{BufWriter, Result};
use std::mem;
use std::time::Duration;
use zerocopy::IntoBytes;
use zerocopy_derive::{Immutable, IntoBytes};

pub struct USBPcapWriter {
    writer: PcapNgWriter<BufWriter<File>>,
}

#[repr(C, packed)]
#[derive(IntoBytes, Immutable)]
struct USBPcapPacketHeader {
    header_length: u16,
    io_packet_id: u64,
    usb_status: u32,
    urb_function: u16,
    info: u8,
    bus: u16,
    device: u16,
    endpoint: u8,
    transfer: u8,
    data_length: u32,
}

impl USBPcapWriter {
    pub fn new(file: BufWriter<File>) -> Result<Self> {
        let mut writer = PcapNgWriter::new(file).unwrap();

        let interface = InterfaceDescriptionBlock {
            linktype: DataLink::USBPCAP,
            snaplen: 0xFFFF,
            options: vec![],
        };
        writer.write_pcapng_block(interface).expect("Must be able to write interface type");
        Ok(
            USBPcapWriter {
                writer
            }
        )
    }

    pub fn write_urbs(&mut self, urbs: &Vec<USBRequestBlock>) -> Result<()> {
        let mut control_xfer: Option<u64> = None;
        let mut control_cat = Vec::<u8>::new();
        for urb in urbs {
            let size = mem::size_of::<USBPcapPacketHeader>();

            let transfer_type = match &urb.transfer_type {
                USBTransferType::Bulk => 3,
                USBTransferType::Control => 2,
                USBTransferType::Interrupt => 1,
                USBTransferType::Isochronous => 0,
            };
            let function_id = urb.usb_function.clone() as u16;

            let mut endpoint = urb.endpoint_number.clone() as u8;
            if urb.direction == USBDirection::DirectionIn {
                endpoint = endpoint + 0x80;
            }

            let control_type = match urb.control_stage {
                None => { None }
                Some(USBControlStage::Data) => { Some(1) }
                Some(USBControlStage::Setup) => { Some(0) }
                Some(USBControlStage::Status) => { Some(2) }
                Some(USBControlStage::Complete) => { Some(3) }
            };

            let info: u8 = if urb.direction == USBDirection::DirectionIn { 1 } else { 0 };

            let header = USBPcapPacketHeader {
                header_length: size as u16,
                data_length: urb.data.len() as u32,
                transfer: transfer_type,
                io_packet_id: urb.index as u64,
                bus: 0,
                device: urb.device_number as u16,
                endpoint,
                usb_status: 0,
                info,
                urb_function: function_id,
            };

            let mut packet_bytes = header.as_bytes().to_vec();
            if control_type.is_some() {
                let mut additional = vec![control_type.unwrap() as u8];
                packet_bytes.append(&mut additional);
            }

            packet_bytes.append(&mut urb.data.clone());

            let packet = EnhancedPacketBlock {
                interface_id: 0,
                timestamp: Duration::from_nanos(urb.index_ns as u64),
                original_len: packet_bytes.len() as u32,
                data: Cow::Owned(packet_bytes),
                options: vec![],
            };
            self.writer.write_pcapng_block(packet).expect("Must be able to write packet");
        }
        Ok(())
    }
}
