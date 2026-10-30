//! Prints a per-file survey of status bytes, packet status words and bus events in .tdc captures.
//! With `--events`, lists the bus-event records of the last capture (the one Data Center exports).

use demuxusb_rs::tdc::{bus_event_name, Element, TdcFile};
use std::collections::BTreeMap;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let events = args.first().is_some_and(|a| a == "--events");
    if events {
        args.remove(0);
    }
    for path in args {
        let file = match TdcFile::open(&path) {
            Ok(file) => file,
            Err(err) => {
                println!("{path}: {err:?}");
                continue;
            }
        };
        let last = file.last_capture().map(|c| c.id);
        let mut status_bytes: BTreeMap<u8, usize> = BTreeMap::new();
        let mut packet_status: BTreeMap<u32, usize> = BTreeMap::new();
        let mut bus_events: BTreeMap<(u8, u32), usize> = BTreeMap::new();
        for record in file.records() {
            let Ok(record) = record else { break };
            if events {
                let codes: Vec<String> = record
                    .elements
                    .iter()
                    .filter_map(|e| match e {
                        Element::BusEvent { code, status } => Some(format!(
                            "{code:#x} {} [{status}]",
                            bus_event_name(*code).unwrap_or("?")
                        )),
                        _ => None,
                    })
                    .collect();
                if !codes.is_empty() && Some(record.capture as u32) == last {
                    println!(
                        "seq={} status={:02x?} {}",
                        record.sequence,
                        record.status().map(|s| s.raw),
                        codes.join(" ")
                    );
                }
                continue;
            }
            for element in &record.elements {
                match element {
                    Element::Status(s) => *status_bytes.entry(s.raw).or_default() += 1,
                    Element::Packet { status, .. } => *packet_status.entry(status.0).or_default() += 1,
                    Element::BusEvent { code, status } => *bus_events.entry((*code, status.0)).or_default() += 1,
                    _ => {}
                }
            }
        }
        if !events {
            println!("{path}\n  status byte {status_bytes:x?}\n  packet status {packet_status:x?}\n  bus events {bus_events:x?}");
        }
    }
}
