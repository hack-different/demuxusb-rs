//! Talks to a Beagle analyzer without the vendor library.
//!
//! * `beagle list`: lists attached analyzers.
//! * `beagle info`: opens each one (firmware 2.x only) and prints what it reports. This sends
//!   only read-only queries.
//! * `beagle parse-dump FILE`: decodes a raw capture stream. The vendor library writes one when
//!   `TP_BG5000_USB2_RAW_DUMP` names a file, which makes a fixture for checking this parser
//!   against what the library itself reports.

use demuxusb_rs::beagle::stream::{HwRecord, Parser};
use demuxusb_rs::beagle::usb::{find_devices, Beagle, QUERY_0E, QUERY_15};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("list") => list(false),
        Some("info") => list(true),
        Some("parse-dump") => parse_dump(args.get(1).ok_or("parse-dump needs a file")?),
        _ => Err("usage: beagle list | info | parse-dump FILE".into()),
    }
}

fn list(open: bool) -> Result<(), Box<dyn Error>> {
    let devices = find_devices()?;
    if devices.is_empty() {
        println!("no Beagle analyzers attached");
    }
    for info in devices {
        println!(
            "{:04x}:{:04x} firmware {} unique id {} type {:?}{}",
            info.device.vendor_id(),
            info.device.product_id(),
            info.firmware,
            info.unique_id.map_or("?".to_string(), |id| format!("{:04}-{:06}", id / 1_000_000, id % 1_000_000)),
            info.device_type(),
            if info.unprogrammed { " (unprogrammed FX2)" } else { "" }
        );
        if !open {
            continue;
        }
        if !info.firmware.is_v2() {
            println!("  firmware {} needs an image uploaded on open, which is not implemented", info.firmware);
            continue;
        }
        let beagle = Beagle::open(info)?;
        println!("  info block {:02x?}", beagle.info_block()?);
        println!("  query 0x0e = {:#04x}", beagle.query(QUERY_0E)?);
        println!("  query 0x15 = {:#04x}", beagle.query(QUERY_15)?);
    }
    Ok(())
}

fn parse_dump(path: &str) -> Result<(), Box<dyn Error>> {
    let mut parser = Parser::new();
    parser.push(&std::fs::read(path)?);
    for timed in parser.by_ref() {
        match &timed.record {
            HwRecord::Packet { data, .. } => println!(
                "{:>14} packet {} [{}]",
                timed.time,
                hex::encode(data),
                timed.record.packet_status().unwrap_or_default()
            ),
            other => println!("{:>14} {other:x?}", timed.time),
        }
    }
    Ok(())
}
