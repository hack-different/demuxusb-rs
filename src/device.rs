use std::collections::HashMap;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use zerocopy::{FromBytes, IntoByteSlice, TryFromBytes};
use crate::pcap_writer::USBPcapPacketHeader;
pub(crate) use crate::usb_request_block::{USBConfiguration, USBInterface, USBRequestBlock, USBControlRequest, USBControlRequestType};

struct Packet {
    data: Vec<u8>
}
trait InterfaceExpert {}
struct Endpoint {
    endpoint_id: u8,
    packets: Vec<Packet>
}

struct Interface {
  descriptor:  USBInterface,
    endpoints: HashMap<u8, Endpoint>,
    expert: Option<Box<dyn InterfaceExpert>>
}

struct Configuration {
    descriptor: USBConfiguration,
    expert: Option<Box<dyn InterfaceExpert>>,
    interfaces: HashMap<u8, Interface>,
}

pub struct Device {
    device_id: u8,
    current_configuration: u8,
    configurations: HashMap<u8, Configuration>,
    strings: HashMap<u8, HashMap<u8, String>>,
}

pub fn parse_devices(packets: Vec<EnhancedPacketBlock>) -> HashMap<u8, Vec<Device>> {
    let mut devices = HashMap::<u8, Vec<Device>>::new();
    for raw_packet in packets {
        let data_parts = raw_packet.data.into_byte_slice().split_at(27);
        let packet = USBPcapPacketHeader::ref_from_bytes(data_parts.0).unwrap();
        if packet.endpoint == 0 && packet.transfer == 0x02 {
            let control_split = data_parts.1.split_at(1);
            let header = USBControlRequest::try_ref_from_bytes(control_split.1).expect("Failed to parse control request");
            match header.request_type {
                USBControlRequestType::UsbReqGetStatus => {
                    println!("GET_STATUS");
                }
                USBControlRequestType::UsbReqSetAddress => {
                    let device_id = header.value as u8;

                    if !devices.contains_key(&device_id) {
                        devices.insert(device_id, Vec::new());
                    }
                    devices.get_mut(&device_id).unwrap().push(
                        Device{
                            device_id,
                            configurations: HashMap::new(),
                            strings: HashMap::new(),
                            current_configuration: 0,
                        }
                    )
                }
                _ => {}
            }
        }
    }
    devices
}

impl Device {

}