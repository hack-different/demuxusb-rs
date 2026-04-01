use anyhow::{Context, Result};
use csv::StringRecord;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use crate::usb_request_block::USBSpeed;

#[derive(Debug)]
pub enum OperationType {
    GetStringDescriptor,
    StartOfFramePacket,
    InputPacket,
    SetupTransaction,
    OutputTransaction,
    AcknowledgePacket,
    Data1Packet,
    SetAddress,
    GetDeviceDescriptor,
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
    ControlTransferStall,
    HostConnected,
    FullSpeedTransition,
    LowSpeedTransition,
    ResetTargetDisconnected,
    ResetKeepAliveTargetDisconnected,
    Suspend,
    ResetChirpJTinyJ,
    Unknown
}

#[derive(Debug)]
pub enum PacketError {

}

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
    csv_reader: csv::Reader<BufReader<File>>
}

type DeviceId = u8;
type EndpointId = u8;

#[derive(Debug)]
pub struct USBPacket {
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
    pub summary: String,
    pub data_offset: Option<u64>,
    pub children: Vec<USBPacket>,
}


impl USBPacket {
    pub fn new(
        record: StringRecord,
        current_offset: u64,
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
        let error: Option<PacketError> =  None;

        let device_id: Option<DeviceId> = record[7].parse().ok();
        let endpoint_id: Option<EndpointId> = record[8].parse().ok();

        let mut extra: Option<String> = None;
        let operation_string: String = record[9].parse().unwrap();
        let operation_name = if operation_string.contains("[") && operation_string.contains("]") {
            let parts: Vec<&str> = operation_string.split("[").collect();
            extra = Some(parts[1].strip_suffix("]").unwrap().trim().to_string());
            parts[0].trim().to_string()
        } else {
            operation_string.trim().to_string()
        };
        let operation = operation_to_operation_type(operation_name);

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

        let children : Vec<USBPacket> = Vec::new();

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
            operation
        }
    }

    pub fn add_child(&mut self, child: USBPacket) {
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
        "ACK packet" => OperationType::AcknowledgePacket,
        "SETUP packet" => OperationType::SetupPacket,
        "Comment" => OperationType::Comment,
        "<Host connected>" => OperationType::HostConnected,
        "<Full-speed>" => OperationType::FullSpeedTransition,
        "<Reset> / <Target disconnected>" => OperationType::ResetTargetDisconnected,
        "Capture started (Sequential)" => OperationType::CaptureStartedSequential,
        "<Low-speed>" => OperationType::LowSpeedTransition,
        "<Reset> / <Keep-alive> / <Target disconnected>" => OperationType::ResetKeepAliveTargetDisconnected,
        "<Suspend>" => OperationType::Suspend,
        "<Reset> / <Chirp J> / <Tiny J>" => OperationType::ResetChirpJTinyJ,
        "SOF packet" => OperationType::StartOfFramePacket,
        "Control Transfer (STALL)" => OperationType::ControlTransferStall,
        "" => OperationType::Unknown,
        _ => panic!("Unknown operation type: {}", operation)
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
            binary_reader
        })
    }

    pub fn read(&mut self) -> Result<Vec<USBPacket>, Box<dyn Error>> {
        let mut offset: u64 = 0;
        let mut packets: Vec<USBPacket> = Vec::new();
        for result in self.csv_reader.records() {
            let record = USBPacket::new(result?, offset);

            if let Some(length) = record.length {
                offset = offset + length;
            }
            packets.push(record);
        }
        Ok(packets)
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
            return None
        }
        else if ts.ends_with(" ms") {
            let parts: Vec<&str> = ts.strip_suffix(" ms").expect("Tested for suffix").split('.').collect();
            let ms_part: u32 = parts[0].parse().unwrap();
            let ns_part: u32 = parts[1].parse().unwrap();
            let us_part: u32 = parts[2].parse().unwrap();
            let total: u64 = (us_part + (1000 + ns_part) + (1000 + ms_part * 1000)) as u64;
            return Some(total);
        }
        else if ts.ends_with(" us") {
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
