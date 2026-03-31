use anyhow::{Context, Result};
use csv::StringRecord;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};

#[derive(Debug)]
pub struct USBPacket {
    pub index: usize,
    pub operation: String,
    pub device_id: usize,
    pub endpoint_id: usize,
    pub duration_ms: u64,
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub duration: String,
    pub children: Vec<USBPacket>,
}

impl USBPacket {
    pub fn new(
        idx: usize,
        op: String,
        dev: usize,
        ep: usize,
        timestamp: &str,
        duration: String,
        data: Vec<u8>,
    ) -> Self {
        let mut pkt = USBPacket {
            index: idx,
            operation: op,
            device_id: dev,
            endpoint_id: ep,
            duration_ms: 0,
            data,
            children: Vec::new(),
            timestamp: 0,
            duration,
        };
        pkt.duration_ms = time_from_totalphase_timestamp(timestamp);
        pkt
    }

    pub fn add_child(&mut self, child: USBPacket) {
        self.children.push(child);
    }

    pub fn dict_data(&self) -> HashMap<&str, String> {
        let mut m = HashMap::new();
        m.insert("idx", format!("{}", self.index));
        m.insert("op", self.operation.clone());
        m.insert("dev", format!("{}", self.device_id));
        m.insert("ep", format!("{}", self.endpoint_id));
        m.insert("timestamp", format!("{}", self.duration_ms));
        m.insert("data", format!("{} bytes", self.data.len()));
        m.insert("duration", self.duration.clone());
        m
    }
}

pub fn time_from_totalphase_timestamp(ts: &str) -> u64 {
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

fn record_field<'a>(row: &'a HashMap<String, String>, key: &str) -> &'a str {
    row.get(key).map(|s| s.as_str()).unwrap_or("")
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PacketRecord {
    TransactionWithData,
    TransactionWithoutData,
    Ignore,
    Unhandled,
}

impl PacketRecord {
    fn from_record(record: &str) -> Self {
        match record {
            r if r.starts_with("OUT tx")
                || r.starts_with("IN txn")
                || r == "Control Transfer"
                || r == "Get Device Descriptor"
                || r == "Set Address"
                || r == "Get String Descriptor"
                || r == "Get Device Qualifier Descriptor"
                || r == "Get Configuration Descriptor"
                || r == "Set Configuration"
                || r == "   IN txn"
                || r == "   OUT tx"
                || r == "   SETUP txn" =>
                {
                    PacketRecord::TransactionWithData
                }
            "   DATA0 packet"
            | "   DATA1 packet"
            | "   OUT packet"
            | "   IN packet"
            | "   ACK packet"
            | "      DATA0 packet"
            | "      DATA1 packet"
            | "      OUT packet"
            | "      IN packet"
            | "      SETUP packet"
            | "      ACK packet" => PacketRecord::TransactionWithoutData,
            r if r.contains("IN-NAK]") || r == "Capture started (Aggregate)" => PacketRecord::Ignore,
            _ => PacketRecord::Unhandled,
        }
    }

    fn operation_name(record: &str) -> String {
        if record.starts_with("OUT tx")
            || record.starts_with("IN txn")
            || record.starts_with("   IN txn")
            || record.starts_with("   OUT tx")
            || record == "   SETUP txn"
        {
            record
                .split_whitespace()
                .take(2)
                .collect::<Vec<&str>>()
                .join("_")
        } else {
            record.replace(' ', "_")
        }
    }

    fn consumes_bytes(self) -> bool {
        matches!(
            self,
            PacketRecord::TransactionWithData | PacketRecord::TransactionWithoutData
        )
    }

    fn emits_packet(self) -> bool {
        matches!(self, PacketRecord::TransactionWithData)
    }

    fn affects_offset(self) -> bool {
        matches!(
            self,
            PacketRecord::TransactionWithData | PacketRecord::TransactionWithoutData
        )
    }
}

pub fn get_next_packet(
    f: &mut BufReader<File>,
    cr: &[HashMap<String, String>],
    offset_list: &[(usize, usize)],
) -> Result<Vec<USBPacket>> {
    fn parse_len(row: &HashMap<String, String>) -> usize {
        record_field(row, "Len")
            .split_whitespace()
            .next()
            .unwrap_or("0")
            .parse::<usize>()
            .unwrap_or(0)
    }

    fn build_packet(row: &HashMap<String, String>, record: &str, data: Vec<u8>) -> USBPacket {
        USBPacket::new(
            row.get("Index").and_then(|s| s.parse().ok()).unwrap_or(0),
            PacketRecord::operation_name(record),
            row.get("Dev").and_then(|s| s.parse().ok()).unwrap_or(0),
            row.get("Ep").and_then(|s| s.parse().ok()).unwrap_or(0),
            record_field(row, "m:s.ms.us"),
            record_field(row, "Dur").to_string(),
            data,
        )
    }

    let mut packet_level0 = Vec::new();

    for &(si, ei) in offset_list {
        for row in &cr[si..=ei] {
            let record = record_field(row, "Record");
            let packet_record = PacketRecord::from_record(record);
            let read_len = parse_len(row);
            let mut read_buf = vec![0u8; read_len];

            if packet_record.consumes_bytes() {
                f.read_exact(&mut read_buf).ok();
            }

            if packet_record.emits_packet() {
                packet_level0.push(build_packet(row, record, read_buf));
            } else if packet_record == PacketRecord::Unhandled {
                eprintln!("Unhandled record: {}", record);
            }
        }
    }

    Ok(packet_level0)
}

pub fn get_transmission_offset_tuples(cr: &[HashMap<String, String>]) -> Vec<(usize, usize)> {
    let mut record_offset: Vec<(usize, usize)> = Vec::new();
    let mut prev_rid: usize = 0;
    let mut last_txn: usize = 0;

    for (rid, row) in cr.iter().enumerate() {
        if row.contains_key("Record") && row.contains_key("Len") && !row.get("Len").unwrap().is_empty() {
            let record = record_field(row, "Record");

            if record.starts_with("OUT tx") || record.starts_with("IN txn") {
                if last_txn != rid {
                    record_offset.push((last_txn, prev_rid));
                    last_txn = rid;
                }
            } else if record == "Control Transfer"
                || record == "Get Device Descriptor"
                || record == "Set Address"
                || record == "Get String Descriptor"
                || record == "Get Device Qualifier Descriptor"
                || record == "Get Configuration Descriptor"
                || record == "Set Configuration"
            {
                if last_txn != rid {
                    record_offset.push((last_txn, prev_rid));
                    last_txn = rid;
                }
            } else if ["   OUT packet", "   IN packet", "      OUT packet", "      IN packet"].contains(&record) {
                prev_rid = rid;
            } else if record.trim() == "DATA0 packet" || record.trim() == "DATA1 packet" {
                prev_rid = rid;
            } else if record == "   ACK packet" || record == "      ACK packet" {
                prev_rid = rid;
            } else if record.starts_with("   IN txn") || record.starts_with("   OUT tx") {
                prev_rid = rid;
            } else if record == "   SETUP txn" {
                prev_rid = rid;
            } else if record == "      SETUP packet" {
                prev_rid = rid;
            } else {
                if last_txn != rid {
                    record_offset.push((last_txn, prev_rid));
                }
                last_txn = rid;
            }
        }
    }

    record_offset
}

pub fn parse_totalphase_files(file_basename: &str) -> Result<Vec<USBPacket>> {
    let bin_path = format!("{}.bin", file_basename);
    let csv_path = format!("{}.csv", file_basename);

    let mut f = BufReader::new(File::open(&bin_path).context("opening bin file")?);

    let mut rdr = csv::Reader::from_path(&csv_path).context("opening csv file")?;
    let headers = rdr.headers()?.clone();

    let mut cr: Vec<HashMap<String, String>> = Vec::new();

    for result in rdr.records() {
        let record: StringRecord = result?;
        let mut map = HashMap::new();
        for (h, v) in headers.iter().zip(record.iter()) {
            map.insert(h.to_string(), v.to_string());
        }
        cr.push(map);
    }

    let offsets = get_transmission_offset_tuples(&cr);
    get_next_packet(&mut f, &cr, &offsets)
}
