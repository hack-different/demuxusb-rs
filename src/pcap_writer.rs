use std::io::{Write, Result};
use crate::usb_request_block::{USBRequestBlock, USBDirection};

pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut writer: W) -> Result<Self> {
        // PCAP Global Header
        // magic_number (4 bytes) - 0xa1b2c3d4 (microsecond resolution)
        // version_major (2 bytes) - 2
        // version_minor (2 bytes) - 4
        // thiszone (4 bytes) - 0
        // sigfigs (4 bytes) - 0
        // snaplen (4 bytes) - 65535
        // network (4 bytes) - 189 (LINKTYPE_USB_LINUX)
        
        writer.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
        writer.write_all(&2u16.to_le_bytes())?;
        writer.write_all(&4u16.to_le_bytes())?;
        writer.write_all(&0i32.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;
        writer.write_all(&65535u32.to_le_bytes())?;
        writer.write_all(&189u32.to_le_bytes())?;
        
        Ok(Self { writer })
    }

    pub fn write_urb(&mut self, urb: &USBRequestBlock) -> Result<()> {
        let timestamp_sec = (urb.index_ns / 1_000_000_000) as u32;
        let timestamp_usec = ((urb.index_ns % 1_000_000_000) / 1_000) as u32;
        
        // USB-Linux header (DLT 189) can be 48 or 64 bytes. 
        // Wireshark generally expects 64 bytes for modern captures.
        let mut usb_header = [0u8; 64];
        
        let id = urb.index as u64;
        let transfer_type = if urb.endpoint_number == 0 { 2u8 } else { 3u8 };
        let ep_addr = if urb.direction == USBDirection::DirectionIn {
            urb.endpoint_number | 0x80
        } else {
            urb.endpoint_number
        };
        let bus_number = 1u16;
        let is_control = urb.endpoint_number == 0;
        let setup_flag = if is_control && urb.data.len() >= 8 { 0 } else { 1 };
        let status = 0i32;
        let urb_len = urb.data.len() as u32;

        usb_header[0..8].copy_from_slice(&id.to_le_bytes());
        usb_header[8] = b'C'; // Completed
        usb_header[9] = transfer_type;
        usb_header[10] = ep_addr;
        usb_header[11] = urb.device_number;
        usb_header[12..14].copy_from_slice(&bus_number.to_le_bytes());
        usb_header[14] = setup_flag;
        usb_header[15] = if urb.data.is_empty() { 1 } else { 0 };
        usb_header[16..24].copy_from_slice(&(timestamp_sec as u64).to_le_bytes());
        usb_header[24..28].copy_from_slice(&timestamp_usec.to_le_bytes());
        usb_header[28..32].copy_from_slice(&status.to_le_bytes());
        usb_header[32..36].copy_from_slice(&urb_len.to_le_bytes());
        usb_header[36..40].copy_from_slice(&urb_len.to_le_bytes());

        if is_control && urb.data.len() >= 8 {
            usb_header[40..48].copy_from_slice(&urb.data[0..8]);
        }
        
        let header_len = 64;
        let packet_len = header_len + urb.data.len() as u32;
        
        // PCAP Packet Header
        self.writer.write_all(&timestamp_sec.to_le_bytes())?;
        self.writer.write_all(&timestamp_usec.to_le_bytes())?;
        self.writer.write_all(&packet_len.to_le_bytes())?;
        self.writer.write_all(&packet_len.to_le_bytes())?;
        
        // PCAP Packet Data (USB-Linux header + USB Data)
        self.writer.write_all(&usb_header)?;
        self.writer.write_all(&urb.data)?;
        
        Ok(())
    }
}
