use std::fs::File;
use csv::ReaderBuilder;
use crate::usb_request_block::{USBDirection, USBRequestBlock, USBSpeed};

pub(crate) struct TotalPhaseCsvReader {
    reader: csv::Reader<File>
}

impl TotalPhaseCsvReader {
    pub(crate) fn new(file_path: &str) -> Result<Self, csv::Error> {
        let file = std::fs::File::open(file_path)
            .map_err(csv::Error::from)?;
        let reader = ReaderBuilder::new()
            .flexible(true)
            .from_reader(file);
        Ok(Self { reader })
    }


fn from_csv_record(record: &csv::StringRecord) -> Option<USBRequestBlock> {
        let level: u8 = record[0].parse().unwrap();
        let index: u32 = record[2].parse().unwrap();
        let time_offset: String = record[3].parse().unwrap();
        let duration: String = record[4].parse().unwrap();
        let device: Option<u8> = record[7].parse().ok();
        let endpoint: Option<u8> = record[8].parse().ok();
        let packet_type: String = record[9].parse().unwrap();
        let duration_ns = 0;
        let index_ns = 0;

        if device.is_none() || endpoint.is_none() {
            return None;
        }

        let endpoint_number = endpoint.unwrap();
        let device_number = device.unwrap();

        let speed = match record.get(1) {
            Some("LS") => USBSpeed::SpeedLow,
            Some("FS") => USBSpeed::SpeedLow,
            Some("HS") => USBSpeed::SpeedHigh,
            Some("SS") => USBSpeed::SpeedSuper,
            _ => USBSpeed::SpeedUnknown,
        };

        let direction = match record.get(9) {
            Some(x) if x.contains("IN") => USBDirection::DirectionIn,
            Some(x) if x.contains("OUT") => USBDirection::DirectionOut,
            _ => USBDirection::DirectionNone
        };

        let data = hex::decode(record[10].replace(" ", "")).unwrap_or_else(|err| Vec::new());

        Some(USBRequestBlock {
            speed,
            direction,
            device_number,
            endpoint_number,
            data,
            index,
            duration_ns,
            index_ns
        })
    }

    pub(crate) fn parse(&mut self) -> Vec<USBRequestBlock> {
        let mut results = Vec::new();

        for result in self.reader.records() {
            if let Ok(record) = result {
                let field: String = record[0].parse().unwrap();
                if field.starts_with("#") || !field.eq("0") {
                    continue;
                }
                let parsed = Self::from_csv_record(&record);

                if parsed.is_some() {
                    results.push(parsed.unwrap());
                }
            } else {
                println!("Error parsing CSV record: {:?}", result);
            }
        }
        return results;
    }
}

