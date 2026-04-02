use crate::usb_request_block::{USBControlStage, USBDirection, USBFunction, USBRequestBlock, USBSpeed, USBTransferType};
use anyhow::{Context, Result};
use csv::StringRecord;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use strum_macros::Display;

#[derive(Debug, PartialEq, Eq)]
pub enum CaptureState {
    Stopped,
    Suspended,
    Started,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResetType {
    KeepAliveTargetDisconnected,
    ChirpJTinyJ,
    TargetDisconnected,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    Disconnected,
}

#[derive(Debug, PartialEq, Eq, Display)]
pub enum OperationType {
    GetStringDescriptor,
    NegativeAcknowledge,
    StartOfFramePacket,
    SetIdle,
    InputPacket,
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
    Comment,
    CaptureStartedSequential,
    HostState(ConnectionState),
    SpeedTransition(USBSpeed),
    Reset(ResetType),
    CaptureState(CaptureState),
    StallPacket,
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

#[derive(Debug)]
pub struct USBPacket<'a> {
    pub level: u8,
    pub speed: USBSpeed,
    pub index: u64,
    pub timestamp: u64,
    pub duration_us: Option<u64>,
    pub length: Option<u64>,
    pub error: Option<PacketError>,
    pub device_id: Option<DeviceId>,
    pub endpoint_id: Option<EndpointId>,
    pub operation: OperationType,
    pub extra: Option<String>,
    pub short_data: DataRecord,
    pub data: Option<Vec<u8>>,
    pub summary: String,
    pub stall: bool,
    pub data_offset: Option<u64>,
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
            extra = Some(parts[1].strip_suffix("]").unwrap().trim().to_string());
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
        "Get Device Descriptor" => OperationType::GetDeviceDescriptor,
        "SETUP txn" => OperationType::SetupTransaction,
        "OUT tx" => OperationType::OutputTransaction,
        "OUT txn" => OperationType::OutputTransaction,
        "Get Hub Descriptor" => OperationType::GetHubDescriptor,
        "Set Port Feature" => OperationType::SetPortFeature,
        "Get Hub Status" => OperationType::GetHubStatus,
        "OUT-DATA-NAK" => OperationType::OutputDataNegativeAcknowledge,
        "Get Device Status" => OperationType::GetDeviceStatus,
        "IN txn" => OperationType::InputTransaction,
        "Control Transfer" => OperationType::ControlTransfer,
        "Get String Descriptor" => OperationType::GetStringDescriptor,
        "Get Device Qualifier Descriptor" => OperationType::GetDeviceQualifierDescriptor,
        "Get Configuration Descriptor" => OperationType::GetConfigurationDescriptor,
        "Set Configuration" => OperationType::SetConfiguration,
        "DATA0 packet" => OperationType::Data0Packet,
        "DATA1 packet" => OperationType::Data1Packet,
        "OUT packet" => OperationType::OutputPacket,
        "IN packet" => OperationType::InputPacket,
        "Set Idle" => OperationType::SetIdle,
        "Hub Status" => OperationType::HubStatus,
        "Get Port Status" => OperationType::GetPortStatus,
        "ACK packet" => OperationType::AcknowledgePacket,
        "Clear Port Feature" => OperationType::ClearPortFeature,
        "SETUP packet" => OperationType::SetupPacket,
        "Comment" => OperationType::Comment,
        "NAK packet" => OperationType::NegativeAcknowledge,
        "IN-NAK" => OperationType::InputNegativeAcknowledge,
        "Get Report Descriptor" => OperationType::GetReportDescriptor,
        "<Host connected>" => OperationType::HostState(ConnectionState::Connected),
        "<Full-speed>" => OperationType::SpeedTransition(USBSpeed::SpeedFull),
        "<Reset> / <Target disconnected>" => OperationType::Reset(ResetType::TargetDisconnected),
        "Input Report" => OperationType::InputReport,
        "Capture started (Sequential)" => OperationType::CaptureStartedSequential,
        "<Low-speed>" => OperationType::SpeedTransition(USBSpeed::SpeedLow),
        "<Reset> / <Keep-alive> / <Target disconnected>" => OperationType::Reset(ResetType::KeepAliveTargetDisconnected),
        "<Suspend>" => OperationType::CaptureState(CaptureState::Suspended),
        "Capture stopped" => OperationType::CaptureState(CaptureState::Stopped),
        "Set Output Report" => OperationType::SetOutputReport,
        "<Reset> / <Chirp J> / <Tiny J>" => OperationType::Reset(ResetType::ChirpJTinyJ),
        "SOF packet" => OperationType::StartOfFramePacket,
        "STALL packet" => OperationType::StallPacket,
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

        let csv_reader = csv::Reader::from_reader(csv_file);
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


    pub fn read_data(&mut self, packet: USBPacket) -> Option<Vec<u8>> {
        if packet.data_offset.is_none() { return None; }
        self.binary_reader.seek(SeekFrom::Start(packet.data_offset.unwrap())).expect("Must be valid");
        let mut result: Vec<u8> = Vec::with_capacity(packet.length.unwrap() as usize);
        self.binary_reader.read(&mut result).expect("Must be read");
        return Some(result);
    }

    pub fn usb_request_blocks(&mut self) -> Result<Vec<USBRequestBlock>, Box<dyn Error>> {
        let mut results: Vec<USBRequestBlock> = Vec::new();
        let packets = self.read()?;
        for result in packets {
            let item = match result.operation {
                OperationType::OutputPacket => {
                    Some(USBRequestBlock {
                        direction: USBDirection::DirectionOut,
                        data: result.data.unwrap(),
                        speed: result.speed,
                        device_number: result.device_id.unwrap(),
                        endpoint_number: result.endpoint_id.unwrap(),
                        index: result.index as u32,
                        transfer_type: USBTransferType::Bulk,
                        control_stage: None,
                        index_ns: result.timestamp,
                        duration_ns: result.duration_us.unwrap_or(0),
                        usb_function: total_phase_to_usb_function(result.operation),
                    })
                }
                OperationType::SetupTransaction => {
                    Some(USBRequestBlock {
                        direction: USBDirection::DirectionOut,
                        data: result.data.unwrap(),
                        speed: result.speed,
                        device_number: result.device_id.unwrap(),
                        endpoint_number: result.endpoint_id.unwrap(),
                        index: result.index as u32,
                        transfer_type: USBTransferType::Control,
                        control_stage: Some(USBControlStage::Setup),
                        index_ns: result.timestamp,
                        duration_ns: result.duration_us.unwrap_or(0),
                        usb_function: total_phase_to_usb_function(result.operation),
                    })
                }
                OperationType::InputTransaction => {
                    if result.level == 0 {
                        Some(USBRequestBlock {
                            direction: USBDirection::DirectionIn,
                            data: result.data.unwrap(),
                            speed: result.speed,
                            device_number: result.device_id.unwrap(),
                            endpoint_number: result.endpoint_id.unwrap(),
                            index: result.index as u32,
                            transfer_type: USBTransferType::Bulk,
                            control_stage: None,
                            index_ns: result.timestamp,
                            duration_ns: result.duration_us.unwrap_or(0),
                            usb_function: total_phase_to_usb_function(result.operation),
                        })
                    } else {
                        Some(USBRequestBlock {
                            direction: USBDirection::DirectionIn,
                            data: result.data.unwrap(),
                            speed: result.speed,
                            device_number: result.device_id.unwrap(),
                            endpoint_number: result.endpoint_id.unwrap(),
                            index: result.index as u32,
                            transfer_type: USBTransferType::Control,
                            control_stage: Some(USBControlStage::Data),
                            index_ns: result.timestamp,
                            duration_ns: result.duration_us.unwrap_or(0),
                            usb_function: total_phase_to_usb_function(result.operation),
                        })
                    }
                }
                OperationType::OutputTransaction => {
                    if result.level == 0 {
                        Some(USBRequestBlock {
                            direction: USBDirection::DirectionOut,
                            data: result.data.unwrap(),
                            speed: result.speed,
                            device_number: result.device_id.unwrap(),
                            endpoint_number: result.endpoint_id.unwrap(),
                            index: result.index as u32,
                            transfer_type: USBTransferType::Bulk,
                            control_stage: None,
                            index_ns: result.timestamp,
                            duration_ns: result.duration_us.unwrap_or(0),
                            usb_function: total_phase_to_usb_function(result.operation),
                        })
                    } else {
                        Some(USBRequestBlock {
                            direction: USBDirection::DirectionIn,
                            data: result.data.unwrap(),
                            speed: result.speed,
                            device_number: result.device_id.unwrap(),
                            endpoint_number: result.endpoint_id.unwrap(),
                            index: result.index as u32,
                            transfer_type: USBTransferType::Control,
                            control_stage: Some(USBControlStage::Complete),
                            index_ns: result.timestamp,
                            duration_ns: result.duration_us.unwrap_or(0),
                            usb_function: total_phase_to_usb_function(result.operation),
                        })
                    }
                }
                _ => None
            };
            if item.is_some() {
                results.push(item.unwrap());
            }
        }
        Ok(results)
    }
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
