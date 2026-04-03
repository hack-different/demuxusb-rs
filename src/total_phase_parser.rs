use crate::usb_request_block::{USBControlStage, USBDirection, USBFunction, USBRequestBlock, USBSpeed, USBTransferType};
use anyhow::{Context, Result};
use csv::StringRecord;
use std::cmp::PartialEq;
use std::collections::HashMap;
use indextree::{Arena, Node, NodeId};
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use derivative::Derivative;
use strum_macros::Display;
use crate::usb_request_block::USBDirection::{DirectionIn, DirectionOut};

#[derive(Debug, PartialEq, Eq, Copy, Clone, Display)]
pub enum CaptureState {
    Stopped,
    Suspended,
    Started,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TriggerType {
    Manual,
    ManualOrUSB2,
    ManualOrUSB3,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum VBusState {
    Present,
    Absent,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ResetType {
    KeepAliveTargetDisconnected,
    KeepaliveChirpKTinyK,
    ChirpJTinyJ,
    ChipKTinyK,
    TargetDisconnected,
    LowFrequencyPeriodicSignalling,
    Default
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ConnectionState {
    Connected,
    Disconnected,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum USB3Signal {
    ChipK,
    TinyK,
    ChirpK,
    TinyJ,
    ChirpJ,
}

#[derive(Debug, PartialEq, Eq, Display, Clone, Copy)]
pub enum OperationType {
    ClearEndpointFeature,
    GetStringDescriptor,
    GetStorageInfo,
    GetDevicePropValue,
    GetObjectPropDesc,
    GetStorageIDs,
    GetDeviceInfo,
    CommandBlock,
    DataBlock,
    GetBOSDescriptor,
    ResponseBlock,
    NotYetPacket,
    InPacket,
    CorruptedPacket,
    PingAcknowledge,
    PingPacket,
    NegativeAcknowledge,
    SetIdle,
    InputPacket,
    SetInterface,
    GetHubDescriptor,
    SetupTransaction,
    SetPortFeature,
    OutputTransaction,
    AcknowledgePacket,
    Data1Packet,
    SetOutputReport,
    GetHubStatus,
    OutputDataNegativeAcknowledge,
    InputReport,
    ClearPortFeature,
    HubStatus,
    SetAddress,
    InputNegativeAcknowledge,
    GetPortStatus,
    GetDeviceDescriptor,
    GetDeviceStatus,
    GetReportDescriptor,
    InputTransaction,
    ControlTransfer,
    GetDeviceQualifierDescriptor,
    SetConfiguration,
    Data0Packet,
    OutputPacket,
    GetConfigurationDescriptor,
    SetupPacket,
    OpenSession,
    StartOfFramePacket,
    Comment,
    TargetState(ConnectionState),
    Trigger(TriggerType),
    LFPSUnknown,
    LFPSPolling,
    USB3Signal(USB3Signal),
    HostState(ConnectionState),
    SpeedTransition(USBSpeed),
    Reset(ResetType),
    VBus(VBusState),
    CaptureState(CaptureState),
    StallPacket,
    LinkTrainingStatusStateMachine,
    Unknown,
}

#[derive(Debug)]
pub enum PacketError {}

#[derive(Debug)]
pub enum DataRecord {
    NoData,
    PartialData(Vec<u8>),
    Data(Vec<u8>),
}

pub struct TotalPhaseReader {
    csv_path: String,
    bin_path: String,
    binary_reader: BufReader<File>,
    csv_reader: csv::Reader<BufReader<File>>,
}

type DeviceId = u8;
type EndpointId = u8;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct USBPacket<'a> {
    pub level: u8,

    pub index: u64,
    pub device_id: Option<DeviceId>,
    pub endpoint_id: Option<EndpointId>,
    pub operation: OperationType,
    pub length: Option<u64>,
    pub timestamp: u64,
    pub duration_us: Option<u64>,

    pub error: Option<PacketError>,


    pub extra: Option<String>,
    #[derivative(Debug="ignore")]
    pub short_data: DataRecord,
    #[derivative(Debug="ignore")]
    pub data: Option<Vec<u8>>,
    pub summary: String,
    pub stall: bool,
    pub speed: USBSpeed,
    pub data_offset: Option<u64>,
    #[derivative(Debug="ignore")]
    pub children: Vec<&'a USBPacket<'a>>,
}


impl<'a> USBPacket<'a> {
    pub fn new(
        record: StringRecord,
        current_offset: u64,
        binary_reader: &mut BufReader<File>,
    ) -> Self {
        // First column is the level, this indicates if the record is nested below the prior record
        let level: u8 = record[0].parse().unwrap();

        // Next is the speed, this may or may not exist in some rows
        let speed = match record.get(1) {
            Some("LS") => USBSpeed::SpeedLow,
            Some("FS") => USBSpeed::SpeedLow,
            Some("HS") => USBSpeed::SpeedHigh,
            Some("SS") => USBSpeed::SpeedSuper,
            _ => USBSpeed::SpeedUnknown,
        };

        // The index of the packet in total ordering
        let index: u64 = record[2].parse().unwrap();

        // The time offset in seconds:milliseconds.nanoseconds.microseconds
        let timestamp = time_from_totalphase_timestamp(&record[3]);

        // Duration in either "XX us" or "XXX.YYY.ZZZ us"
        let duration_us = duration_from_totalphase_duration(record.get(4));

        // Length
        let length = match record.get(5) {
            None => None,
            Some(s) => {
                if s == "" {
                    None
                } else {
                    let value: u64 = s.strip_suffix(" B").unwrap().parse().unwrap();
                    Some(value)
                }
            }
        };

        // TODO: Error parsing
        let error: Option<PacketError> = None;

        let device_id: Option<DeviceId> = record[7].parse().ok();
        let endpoint_id: Option<EndpointId> = record[8].parse().ok();

        let mut extra: Option<String> = None;
        let operation_string: String = record[9].parse().unwrap();
        let mut operation_name = if operation_string.contains("[") && operation_string.contains("]") {
            let parts: Vec<&str> = operation_string.split("[").collect();
            if parts.len() > 1 {
                extra = Some(parts[1].trim().strip_suffix("]").expect(&format!("Strip ] {operation_string}")).trim().to_string());
            } else {
                extra = None;
            }
            parts[0].trim().to_string()
        } else {
            operation_string.trim().to_string()
        };
        let mut stall = operation_name.contains("(STALL)");
        operation_name = operation_name.replace("(STALL)", "").trim().to_string();
        let operation = operation_to_operation_type(operation_name);
        if operation == OperationType::StallPacket {
            stall = true;
        }

        // Data parsing rules, if nothing then nothing, if ends with "..." then partial, otherwise data
        let short_data: DataRecord = match record.get(10) {
            None => DataRecord::NoData,
            Some(data) => {
                if data == "" {
                    DataRecord::NoData
                } else if data.ends_with("...") {
                    let data = hex::decode(data.replace(" ", "").strip_suffix("...").unwrap()).unwrap_or_else(|_| Vec::new());
                    DataRecord::PartialData(data)
                } else {
                    let data = hex::decode(data.replace(" ", "")).unwrap_or_else(|_| Vec::new());
                    DataRecord::Data(data)
                }
            }
        };

        let summary = record[11].to_string();

        let data_offset = match length {
            None => None,
            Some(_) => Some(current_offset),
        };

        let children: Vec<&USBPacket> = Vec::new();

        let data = if length.is_some() {
            binary_reader.seek(SeekFrom::Start(current_offset)).unwrap();
            let mut data = vec![0u8; length.unwrap() as usize];
            binary_reader.read_exact(data.as_mut_slice()).expect("Should read exact data");
            Some(data)
        } else {
            Some(Vec::new())
        };

        USBPacket {
            level,
            index,
            speed,
            device_id,
            endpoint_id,
            timestamp,
            short_data,
            duration_us,
            length,
            error,
            extra,
            summary,
            data_offset,
            children,
            stall,
            operation,
            data,
        }
    }

    pub fn add_child(&mut self, child: &'a USBPacket) {
        self.children.push(child);
    }

    pub fn is_interesting(&self) -> bool {
        let interesting = vec![    OperationType::GetStringDescriptor,
                                   OperationType::NotYetPacket,
                                   OperationType::InPacket,
                                   OperationType::CorruptedPacket,
                                   OperationType::PingAcknowledge,
                                   OperationType::PingPacket,
                                   OperationType::NegativeAcknowledge,
                                   OperationType::SetIdle,
                                   OperationType::InputPacket,
                                   OperationType::SetInterface,
                                   OperationType::GetHubDescriptor,
                                   OperationType::SetupTransaction,
                                   OperationType::SetPortFeature,
                                   OperationType::OutputTransaction,
                                   OperationType::AcknowledgePacket,
                                   OperationType::Data1Packet,
                                   OperationType::SetOutputReport,
                                   OperationType::GetHubStatus,
                                   OperationType::OutputDataNegativeAcknowledge,
                                   OperationType::InputReport,
                                   OperationType::ClearPortFeature,
                                   OperationType::HubStatus,
                                   OperationType::SetAddress,
                                   OperationType::InputNegativeAcknowledge,
                                   OperationType::GetPortStatus,
                                   OperationType::GetDeviceDescriptor,
                                   OperationType::GetDeviceStatus,
                                   OperationType::GetReportDescriptor,
                                   OperationType::InputTransaction,
                                   OperationType::ControlTransfer,
                                   OperationType::GetDeviceQualifierDescriptor,
                                   OperationType::SetConfiguration,
                                   OperationType::Data0Packet,
                                   OperationType::OutputPacket,
                                   OperationType::GetConfigurationDescriptor,
                                   OperationType::SetupPacket];
        if interesting.contains(&self.operation) {
            return true;
        }
        return false;
    }

    pub fn dict_data(&self) -> HashMap<&str, String> {
        let mut m = HashMap::new();
        m.insert("idx", format!("{}", self.index));

        m.insert("dev", format!("{}", self.device_id.unwrap()));
        m.insert("ep", format!("{}", self.endpoint_id.unwrap()));

        m
    }
}

fn operation_to_operation_type(operation: String) -> OperationType {
    match operation.as_str() {
        "Set Address" => OperationType::SetAddress,
        "OpenSession" => OperationType::OpenSession,
        "Command Block" => OperationType::CommandBlock,
        "GetDeviceInfo" => OperationType::GetDeviceInfo,
        "Get BOS Descriptor" => OperationType::GetBOSDescriptor,
        "Response Block" => OperationType::ResponseBlock,
        "LTSSM Transition" => OperationType::LinkTrainingStatusStateMachine,
        "Get Device Descriptor" => OperationType::GetDeviceDescriptor,
        "SETUP txn" => OperationType::SetupTransaction,
        "OUT tx" => OperationType::OutputTransaction,
        "Data Block" => OperationType::DataBlock,
        "OUT txn" => OperationType::OutputTransaction,
        "Get Hub Descriptor" => OperationType::GetHubDescriptor,
        "Set Port Feature" => OperationType::SetPortFeature,
        "Set Interface" => OperationType::SetInterface,
        "Detach" => OperationType::TargetState(ConnectionState::Disconnected),
        "Get Hub Status" => OperationType::GetHubStatus,
        "OUT-DATA-NAK" => OperationType::OutputDataNegativeAcknowledge,
        "Get Device Status" => OperationType::GetDeviceStatus,
        "IN txn" => OperationType::InputTransaction,
        "<Reset>" => OperationType::Reset(ResetType::Default),
        "Control Transfer" => OperationType::ControlTransfer,
        "Get String Descriptor" => OperationType::GetStringDescriptor,
        "Get Device Qualifier Descriptor" => OperationType::GetDeviceQualifierDescriptor,
        "Get Configuration Descriptor" => OperationType::GetConfigurationDescriptor,
        "Set Configuration" => OperationType::SetConfiguration,
        "DATA0 packet" => OperationType::Data0Packet,
        "DATA1 packet" => OperationType::Data1Packet,
        "OUT packet" => OperationType::OutputPacket,
        "IN packet" => OperationType::InputPacket,
        "GetStorageIDs" => OperationType::GetStorageIDs,
        "GetStorageInfo" => OperationType::GetStorageInfo,
        "Set Idle" => OperationType::SetIdle,
        "Hub Status" => OperationType::HubStatus,
        "Get Port Status" => OperationType::GetPortStatus,
        "ACK packet" => OperationType::AcknowledgePacket,
        "Clear Port Feature" => OperationType::ClearPortFeature,
        "SETUP packet" => OperationType::SetupPacket,
        "Comment" => OperationType::Comment,
        "GetObjectPropDesc" => OperationType::GetObjectPropDesc,
        "<HNP> / <Full-speed>" => OperationType::SpeedTransition(USBSpeed::SpeedFull),
        "<LFPS Polling/U1 Exit>" => OperationType::LFPSPolling,
        "<SuperSpeed Host Connected>" => OperationType::HostState(ConnectionState::Connected),
        "<LFPS Reset>" => OperationType::Reset(ResetType::LowFrequencyPeriodicSignalling),
        "<LFPS Polling>" => OperationType::LFPSPolling,
        "<LFPS Unknown>" => OperationType::LFPSUnknown,
        "<High-speed>" => OperationType::SpeedTransition(USBSpeed::SpeedHigh),
        "<Manual Trigger>" => OperationType::Trigger(TriggerType::Manual),
        "OUT txn (NAK)" => OperationType::NegativeAcknowledge,
        "<VBus Absent>" => OperationType::VBus(VBusState::Absent),
        "<Host disconnected>" => OperationType::HostState(ConnectionState::Disconnected),
        "<Reset> / <Keep-alive> / <Chirp K> / <Tiny K>" => OperationType::Reset(ResetType::KeepaliveChirpKTinyK),
        "PING-ACK" => OperationType::PingAcknowledge,
        "<Reset> / <Chirp K> / <Tiny K>" => OperationType::Reset(ResetType::ChipKTinyK),
        "<Chirp K>" => OperationType::USB3Signal(USB3Signal::ChirpK),
        "<Manual Trigger or USB2 Trigger>" => OperationType::Trigger(TriggerType::ManualOrUSB2),
        "<Manual Trigger or USB3 Trigger>" => OperationType::Trigger(TriggerType::ManualOrUSB3),
        "<VBus Present>" => OperationType::VBus(VBusState::Present),
        "NAK packet" => OperationType::NegativeAcknowledge,
        "<Chirp J>" => OperationType::USB3Signal(USB3Signal::ChirpJ),
        "CDC IN Data" => OperationType::InputTransaction,
        "CDC OUT Data" => OperationType::OutputTransaction,
        "Clear Endpoint Feature" => OperationType::ClearEndpointFeature,
        "<SuperSpeed Host Disconnected>" => OperationType::HostState(ConnectionState::Disconnected),
        "IN-NAK" => OperationType::InputNegativeAcknowledge,
        "GetDevicePropValue" => OperationType::GetDevicePropValue,
        "Get Report Descriptor" => OperationType::GetReportDescriptor,
        "<Host connected>" => OperationType::HostState(ConnectionState::Connected),
        "<Full-speed>" => OperationType::SpeedTransition(USBSpeed::SpeedFull),
        "<Reset> / <Target disconnected>" => OperationType::Reset(ResetType::TargetDisconnected),
        "Input Report" => OperationType::InputReport,
        "PING packet" => OperationType::PingPacket,
        "CORRUPTED packet" => OperationType::CorruptedPacket,
        "OUT txn (NYET)" => OperationType::OutputTransaction,
        "NYET packet" => OperationType::NotYetPacket,
        "Capture started (Sequential)" => OperationType::CaptureState(CaptureState::Started),
        "<Low-speed>" => OperationType::SpeedTransition(USBSpeed::SpeedLow),
        "<Reset> / <Keep-alive> / <Target disconnected>" => OperationType::Reset(ResetType::KeepAliveTargetDisconnected),
        "<Suspend>" => OperationType::CaptureState(CaptureState::Suspended),
        "IN" => OperationType::InPacket,
        "Capture stopped" => OperationType::CaptureState(CaptureState::Stopped),
        "Set Output Report" => OperationType::SetOutputReport,
        "<Reset> / <Chirp J> / <Tiny J>" => OperationType::Reset(ResetType::ChirpJTinyJ),
        "SOF packet" => OperationType::StartOfFramePacket,
        "<SuperSpeed Target Connected>" => OperationType::TargetState(ConnectionState::Connected),
        "STALL packet" => OperationType::StallPacket,
        "Capture started (Aggregate)" => OperationType::CaptureState(CaptureState::Started),
        "" => OperationType::Unknown,
        _ => panic!("Unknown operation type: {}", operation)
    }
}

pub fn total_phase_to_usb_function(op: OperationType) -> USBFunction {
    match op {
        OperationType::GetDeviceDescriptor => {
            USBFunction::GetDescriptorFromDevice
        }
        OperationType::SetConfiguration => {
            USBFunction::SelectConfiguration
        }
        OperationType::OutputPacket => {
            USBFunction::BulkOrInterruptTransfer
        }
        OperationType::GetStringDescriptor => {
            USBFunction::GetDescriptorFromDevice
        }
        OperationType::ControlTransfer => {
            USBFunction::ControlTransferEx
        }
        OperationType::GetConfigurationDescriptor => {
            USBFunction::GetConfiguration
        }
        OperationType::Data0Packet => {
            USBFunction::ControlTransfer
        }
        OperationType::Data1Packet => {
            USBFunction::ControlTransfer
        }
        OperationType::OutputTransaction |
        OperationType::InputPacket |
        OperationType::InPacket |
        OperationType::InputTransaction => {
            USBFunction::BulkOrInterruptTransfer
        }
        OperationType::InputReport => {
            USBFunction::BulkOrInterruptTransfer
        }
        _ => USBFunction::Unknown,
    }
}

impl TotalPhaseReader {
    pub(crate) fn new(file_basename: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bin_path = format!("{}.bin", file_basename);
        let csv_path = format!("{}.csv", file_basename);

        let binary_reader = BufReader::new(File::open(&bin_path).context("opening bin file")?);
        let mut csv_file = BufReader::new(File::open(&csv_path).context("opening csv file")?);

        // Skip the first several rows as they are junk
        for _ in 0..6 { // Skip the first two lines
            let mut line = String::new();
            csv_file.read_line(&mut line)?; // Read and discard a line
        }

        let mut csv_builder = csv::ReaderBuilder::new();
        let csv_reader = csv_builder.flexible(true).from_reader(csv_file);
        Ok(Self {
            bin_path,
            csv_reader,
            csv_path,
            binary_reader,
        })
    }

    pub fn read(&mut self) -> Result<Vec<USBPacket>, Box<dyn Error>> {
        let mut offset: u64 = 0;
        let mut packets: Vec<USBPacket> = Vec::new();
        for result in self.csv_reader.records() {
            let record = USBPacket::new(result?, offset, &mut self.binary_reader);

            if let Some(length) = record.length {
                offset = offset + length;
            }

            packets.push(record);
        }
        Ok(packets)
    }

    pub fn read_tree(&mut self, interesting_only: bool) -> Result<Arena<USBPacket>, Box<dyn Error>> {
        let mut packets = self.read()?;
        if interesting_only {
            packets.retain(|packet| packet.is_interesting());
        }


        let mut tree: Arena<USBPacket> = Arena::new();
        let mut parents: Vec<NodeId> = Vec::new();

        for packet in packets {
            if packet.level == 0 {
                let node_id = tree.new_node(packet);
                parents = vec![node_id];
            } else {
                parents.truncate((packet.level) as usize);

                let parent = parents.last().unwrap();

                let new_id = tree.new_node(packet);
                parent.append(new_id, &mut tree);
                parents.push(new_id);
            }
        }
        Ok(tree)
    }


    pub fn read_data(&mut self, packet: USBPacket) -> Option<Vec<u8>> {
        if packet.data_offset.is_none() { return None; }
        self.binary_reader.seek(SeekFrom::Start(packet.data_offset.unwrap())).expect("Must be valid");
        let mut result: Vec<u8> = Vec::with_capacity(packet.length.unwrap() as usize);
        self.binary_reader.read(&mut result).expect("Must be read");
        return Some(result);
    }

    pub fn usb_request_blocks(&mut self) -> Result<Vec<USBRequestBlock>, Box<dyn Error>> {
        let mut results: Vec<USBRequestBlock> = Vec::new();
        let packets = self.read_tree(true)?;
        let root_nodes: Vec<_> = packets
            .iter()
            .filter(|node| node.parent().is_none())
            .collect();
        for node in root_nodes {
            let result = node.get();
            let item = match result.operation {
                OperationType::InputTransaction => {
                    Some(vec![USBRequestBlock {
                        direction: USBDirection::DirectionIn,
                        data: result.data.as_ref().unwrap().clone(),
                        speed: result.speed,
                        device_number: result.device_id.unwrap(),
                        endpoint_number: result.endpoint_id.unwrap(),
                        index: result.index as u32,
                        transfer_type: USBTransferType::Bulk,
                        control_stage: None,
                        index_ns: result.timestamp,
                        duration_ns: result.duration_us.unwrap_or(0),
                        usb_function: total_phase_to_usb_function(result.operation),
                    }])
                }
                OperationType::OutputTransaction => {
                    Some(vec![USBRequestBlock {
                        direction: USBDirection::DirectionOut,
                        data: result.data.as_ref().unwrap().clone(),
                        speed: result.speed,
                        device_number: result.device_id.unwrap(),
                        endpoint_number: result.endpoint_id.unwrap(),
                        index: result.index as u32,
                        transfer_type: USBTransferType::Bulk,
                        control_stage: None,
                        index_ns: result.timestamp,
                        duration_ns: result.duration_us.unwrap_or(0),
                        usb_function: total_phase_to_usb_function(result.operation),
                    }])
                }
                OperationType::ControlTransfer |
                OperationType::GetDeviceDescriptor |
                OperationType::GetConfigurationDescriptor |
                OperationType::SetConfiguration |
                OperationType::SetAddress |
                OperationType::GetHubDescriptor |
                OperationType::GetDeviceQualifierDescriptor |
                OperationType::GetStringDescriptor => {
                    Some(compose_control_transfer(&node, &packets))
                }
                _ => None
            };
            if item.is_some() {
                results.append(&mut item.unwrap());
            }
        }
        Ok(results)
    }
}

fn compose_control_transfer(node: &Node<USBPacket>, arena: &Arena<USBPacket>) -> Vec<USBRequestBlock> {
    let mut results: Vec<USBRequestBlock> = Vec::new();
    let packet = node.get();
    let setup = arena.get(node.first_child().unwrap()).unwrap().get();

    let output_children = arena.get_node_id(node).unwrap().children(arena).map(|n| arena.get(n).unwrap().get());
    let output_data = output_children.filter(|child| child.operation == OperationType::OutputTransaction).collect::<Vec<_>>();
    let mut data = setup.data.clone().unwrap_or_default();
    for node in output_data {
        data.append(&mut node.data.clone().unwrap_or_default());
    }

    results.push(
        USBRequestBlock {
            direction: DirectionOut,
            speed: packet.speed,
            device_number: packet.device_id.unwrap(),
            endpoint_number: packet.endpoint_id.unwrap(),
            index: packet.index as u32,
            transfer_type: USBTransferType::Control,
            control_stage: Some(USBControlStage::Setup),
            index_ns: setup.timestamp,
            duration_ns: setup.duration_us.unwrap_or(0),
            usb_function: total_phase_to_usb_function(packet.operation),
            data
        }
    );

    let input_children = arena.get_node_id(node).unwrap().children(arena).map(|n| arena.get(n).unwrap().get());
    let input_data = input_children.filter(|child| child.operation == OperationType::InputTransaction).collect::<Vec<_>>();
    let mut data = Vec::new();
    let input_packets_length = input_data.len();
    for node in input_data {
        data.append(&mut node.data.clone().unwrap_or_default());
    }
    if input_packets_length > 0 {
        results.push(USBRequestBlock {
            direction: DirectionIn,
            speed: packet.speed,
            device_number: packet.device_id.unwrap(),
            endpoint_number: packet.endpoint_id.unwrap(),
            index: packet.index as u32,
            transfer_type: USBTransferType::Control,
            control_stage: Some(USBControlStage::Data),
            index_ns: setup.timestamp,
            duration_ns: setup.duration_us.unwrap_or(0),
            usb_function: total_phase_to_usb_function(packet.operation),
            data: data.clone()
        })
    }

    results
}

fn time_from_totalphase_timestamp(ts: &str) -> u64 {
    let parts: Vec<&str> = ts.split(':').collect();
    if parts.len() < 2 {
        return 0;
    }
    let t0 = parts[0].parse::<u64>().unwrap_or(0);
    let n: Vec<&str> = parts[1].split('.').collect();
    if n.len() < 3 {
        return 0;
    }
    let n0 = n[0].parse::<u64>().unwrap_or(0);
    let n1 = n[1].parse::<u64>().unwrap_or(0);
    let n2 = n[2].parse::<u64>().unwrap_or(0);

    ((t0 * 1_000_000) * 60) + (n0 * 1_000_000) + (n1 * 1_000) + n2
}

fn duration_from_totalphase_duration(ts: Option<&str>) -> Option<u64> {
    if let Some(ts) = ts {
        if ts == "" {
            return None;
        } else if ts.ends_with(" s") {
            let parts: Vec<&str> = ts.strip_suffix(" s").expect("Tested for suffix").split('.').collect();
            let s_part: u32 = parts[0].parse().unwrap();
            let ms_part: u32 = parts[1].parse().unwrap();
            let ns_part: u32 = parts[2].parse().unwrap();
            let us_part: u32 = parts[3].parse().unwrap();
            let total: u64 = ((s_part * 1000 * 1000 * 1000) + us_part + (1000 + ns_part) + (1000 + ms_part * 1000)) as u64;
            return Some(total);
        } else if ts.ends_with(" ms") {
            let parts: Vec<&str> = ts.strip_suffix(" ms").expect("Tested for suffix").split('.').collect();
            let ms_part: u32 = parts[0].parse().unwrap();
            let ns_part: u32 = parts[1].parse().unwrap();
            let us_part: u32 = parts[2].parse().unwrap();
            let total: u64 = (us_part + (1000 + ns_part) + (1000 + ms_part * 1000)) as u64;
            return Some(total);
        } else if ts.ends_with(" us") {
            let parts: Vec<&str> = ts.strip_suffix(" us").expect("Tested for suffix").split('.').collect();
            let us_part: u32 = parts[0].parse().unwrap();
            let ns_part: u32 = parts[1].parse().unwrap();
            let total: u64 = (us_part + (ns_part * 1000)) as u64;
            return Some(total);
        } else if ts.ends_with(" ns") {
            let result: u64 = ts.strip_suffix(" ns").unwrap().to_string().parse().unwrap();
            return Some(result);
        }
        panic!("Unknown duration format '{ts}'");
    }
    None
}

fn record_field<'a>(row: &'a HashMap<String, String>, key: &str) -> &'a str {
    row.get(key).map(|s| s.as_str()).unwrap_or("")
}

pub fn totalphase_reader(file_basename: &str) -> Result<TotalPhaseReader, Box<dyn Error>> {
    return TotalPhaseReader::new(file_basename);
}
