use std::error::Error;
use anyhow::Result;
mod usb_request_block;
mod total_phase_parser;
mod pcap_writer;
mod device;

use crate::pcap_writer::USBPcapWriter;
use clap::{arg, ArgMatches, Command};
use std::fs::File;
use std::io::BufWriter;
use indextree::Arena;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::PcapNgReader;
use crate::device::parse_devices;
use demuxusb_rs::tdc::{self, bus_event_name, Element, TdcFile};
use std::collections::BTreeMap;

fn print_tree<T: std::fmt::Debug>(node_id: indextree::NodeId, arena: &Arena<T>, indent: &str) {
    let node = &arena[node_id];
    println!("{}+- {:?}", indent, node.get());

    let new_indent = format!("{}  ", indent);
    let mut children = node_id.children(arena);
    while let Some(child) = children.next() {
        print_tree(child, arena, &new_indent);
    }
}

fn cli() -> Command {
    Command::new("demuxusb-rs")
        .about("USB demuxer")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("tree")
                .about("Reads and outputs info about USB stream")
                .arg(arg!(<FILE_BASE> "The base name of the stream files (.bin and .csv)"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("pcap")
                .about("Export USB stream to PCAP format")
                .arg(arg!(<FILE_BASE> "The base name of the stream files (.bin and .csv)"))
                .arg(arg!(<OUTPUT> "The output PCAP file"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("tdc-info")
                .about("Prints the header, capture table and record statistics of a Data Center .tdc file")
                .arg(arg!(<TDC_FILE> "The .tdc capture"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("tdc-dump")
                .about("Prints the records of a Data Center .tdc file, one per line")
                .arg(arg!(<TDC_FILE> "The .tdc capture"))
                .arg(arg!(--capture <ID> "Only print records of this capture").value_parser(clap::value_parser!(u8)))
                .arg(arg!(--packets "Only print records that hold a USB packet"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("tdc-pcap")
                .about("Exports the USB packets of a Data Center .tdc file to pcapng (link-layer USB 2.0)")
                .arg(arg!(<TDC_FILE> "The .tdc capture"))
                .arg(arg!(<OUTPUT> "The output pcapng file"))
                .arg(arg!(--capture <ID> "Only export this capture").value_parser(clap::value_parser!(u8)))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("info")
            .about("Prints info about the USB stream")
            .arg(arg!(<PCAP_FILE> "The base name of the stream files (.bin and .csv)"))
            .arg_required_else_help(true),
        )
}

fn main() -> Result<()> {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("tree", sub_matches)) => {
            let mut filebase = sub_matches.get_one::<String>("FILE_BASE").expect("required").to_string();

            if filebase.ends_with(".csv") {
                filebase = filebase.strip_suffix(".csv").expect("has suffix").to_string();
            }
            if filebase.ends_with(".bin") {
                filebase = filebase.strip_suffix(".bin").unwrap().to_string();
            }

            let mut reader = total_phase_parser::totalphase_reader(&filebase).unwrap();
            let packets = reader.read_tree(true).unwrap();
            let root_nodes: Vec<_> = packets
                .iter()
                .filter(|node| node.parent().is_none())
                .collect();
            for root in root_nodes {
                print_tree(packets.get_node_id(root).unwrap(), &packets, "");
            }
        }

        Some(("pcap", sub_matches)) => {
            let filebase = sub_matches.get_one::<String>("FILE_BASE").expect("required");
            let output_path = sub_matches.get_one::<String>("OUTPUT").expect("required");

            let mut reader = total_phase_parser::totalphase_reader(filebase).unwrap();
            let packets = reader.usb_request_blocks();

            let file = File::create(output_path)?;
            let writer = BufWriter::new(file);
            let mut pcap_writer = USBPcapWriter::new(writer)?;


            pcap_writer.write_urbs(&packets.unwrap()).expect("Conversion failed");
        }
        Some(("info", sub_matches)) => {
            let filebase = sub_matches.get_one::<String>("PCAP_FILE").expect("required").to_string();

            let mut packets: Vec<EnhancedPacketBlock> = Vec::new();

            let mut reader = PcapNgReader::new(File::open(filebase)?)?;
            while let Some(block) = reader.next_block() {
                if let Some(epb) = block?.into_enhanced_packet() {
                    packets.push( epb.into_owned());
                }
            }
            parse_devices(packets);
        }

        Some(("tdc-info", sub_matches)) => {
            let path = sub_matches.get_one::<String>("TDC_FILE").expect("required");
            let file = TdcFile::open(path)?;
            print_tdc_info(&file)?;
        }
        Some(("tdc-dump", sub_matches)) => {
            let path = sub_matches.get_one::<String>("TDC_FILE").expect("required");
            let capture = sub_matches.get_one::<u8>("capture").copied();
            let packets_only = sub_matches.get_flag("packets");
            let file = TdcFile::open(path)?;
            for record in file.records() {
                let record = record?;
                if capture.is_some_and(|id| id != record.capture) || (packets_only && record.packet_data().is_none()) {
                    continue;
                }
                println!("{}", describe_record(&file, &record));
            }
        }
        Some(("tdc-pcap", sub_matches)) => {
            let path = sub_matches.get_one::<String>("TDC_FILE").expect("required");
            let output_path = sub_matches.get_one::<String>("OUTPUT").expect("required");
            let capture = sub_matches.get_one::<u8>("capture").copied();
            let file = TdcFile::open(path)?;
            let written = tdc::pcap::write_pcapng(&file, capture, BufWriter::new(File::create(output_path)?))?;
            println!("wrote {written} packets to {output_path}");
        }

        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachable!()
    }

    Ok(())
}


fn print_tdc_info(file: &TdcFile) -> Result<()> {
    let header = &file.header;
    println!("format version {:#x}, writer {}.{}, saved at unix {}", header.format_version, header.writer_version[0], header.writer_version[1], header.saved_at);
    println!("{} block(s), FastLZ levels {:?}, {} bytes decompressed", file.block_levels.len(), file.block_levels, file.stream().len());
    let tags: Vec<String> = header.element_types.iter().map(|t| format!("{:#04x}", t.tag)).collect();
    println!("element types: {}", tags.join(" "));

    let mut per_capture: BTreeMap<u8, (usize, usize)> = BTreeMap::new();
    let mut per_tag: BTreeMap<u8, usize> = BTreeMap::new();
    for record in file.records() {
        let record = record?;
        let entry = per_capture.entry(record.capture).or_default();
        entry.0 += 1;
        if record.packet_data().is_some() {
            entry.1 += 1;
        }
        for element in &record.elements {
            *per_tag.entry(element.tag()).or_default() += 1;
            if let Element::Comment(text) = element {
                println!("comment (capture {}): {text}", record.capture);
            }
        }
    }

    for capture in &file.captures {
        let (records, packets) = per_capture.get(&(capture.id as u8)).copied().unwrap_or_default();
        println!(
            "capture {}: unix {}..{}, {:.6} s, {} records, {} packets",
            capture.id,
            capture.started_at,
            capture.stopped_at,
            capture.ticks_to_duration(capture.duration_ticks).as_secs_f64(),
            records,
            packets
        );
    }
    let counts: Vec<String> = per_tag.iter().map(|(tag, count)| format!("{tag:#04x}:{count}")).collect();
    println!("elements: {}", counts.join(" "));
    if let Some(footer) = &file.footer {
        println!("footer: version {}, {} bytes", footer.version, footer.data.len());
    }
    Ok(())
}

fn describe_record(file: &TdcFile, record: &tdc::Record) -> String {
    let (time, duration) = match file.capture(record.capture) {
        Some(capture) => (
            capture.ticks_to_duration(record.timestamp).as_secs_f64(),
            capture.ticks_to_duration(record.duration as u64).as_secs_f64(),
        ),
        None => (0.0, 0.0),
    };
    let (speed, error) = record.status().map(|s| (s.speed.to_string(), if s.error { "E" } else { "" })).unwrap_or_default();
    let mut description = Vec::new();
    for element in &record.elements {
        match element {
            Element::Status(_) => {}
            Element::PacketInfo(info) => description.push(format!(
                "dev={:02} ep={:02}{} pid={:#x}",
                info.address,
                info.endpoint,
                if info.direction_in { "in" } else { "" },
                info.pid
            )),
            Element::Packet { data, status } => description.push(format!("packet {} status={status}", hex::encode(data))),
            Element::Transaction { kind, children } => description.push(format!("transaction kind={kind:#x} children={children:?}")),
            Element::SofGroup { count, first_frame, last_frame, .. } => {
                description.push(format!("[{count} SOF] frames {first_frame}-{last_frame}"))
            }
            Element::GroupCount { count, .. } => description.push(format!("[{count} collapsed]")),
            Element::BusEvent { code, status } => description.push(format!(
                "bus event {code:#x} ({}) status={status}",
                bus_event_name(*code).unwrap_or("unknown")
            )),
            Element::Comment(text) => description.push(format!("comment {text:?}")),
            other => description.push(format!("{other:?}")),
        }
    }
    format!(
        "{}:{:<7} {}{:.9} {:.9} {:2} {:1} {}",
        record.capture,
        record.sequence,
        if record.nested { "  " } else { "" },
        time,
        duration,
        speed,
        error,
        description.join(" ")
    )
}
