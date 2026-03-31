use std::fs::File;
use std::io::{BufRead, BufReader};
use csv::ReaderBuilder;
use crate::usb_request_block::{USBDirection, USBRequestBlock, USBSpeed};

pub(crate) struct TotalPhaseCsvReader {
    reader: csv::Reader<BufReader<File>>
}

impl TotalPhaseCsvReader {
    pub(crate) fn new(file_path: &str) -> Result<Self, csv::Error> {
        let file = std::fs::File::open(file_path)
            .map_err(csv::Error::from)?;

        let mut reader = BufReader::new(file);

        // Skip the first several rows as they are junk
        for _ in 0..6 { // Skip the first two lines
            let mut line = String::new();
            reader.read_line(&mut line)?; // Read and discard a line
        }

        let reader = ReaderBuilder::new()
            .from_reader(reader);
        Ok(Self { reader })
    }


    fn from_csv_record(record: &csv::StringRecord) -> Option<USBRequestBlock> {
        let _level: u8 = record[0].parse().unwrap();
        let index: u32 = record[2].parse().unwrap();
        let _time_offset: String = record[3].parse().unwrap();
        let _duration: String = record[4].parse().unwrap();
        let device: Option<u8> = record[7].parse().ok();
        let endpoint: Option<u8> = record[8].parse().ok();
        let _packet_type: String = record[9].parse().unwrap();
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

        let data = hex::decode(record[10].replace(" ", "")).unwrap_or_else(|_| Vec::new());

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

