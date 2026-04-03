use anyhow::Result;
mod usb_request_block;
mod total_phase_parser;
mod pcap_writer;

use crate::pcap_writer::USBPcapWriter;
use clap::{arg, Command};
use std::fs::File;
use std::io::BufWriter;
use indextree::Arena;

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
            Command::new("info")
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
}

fn main() -> Result<()> {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("info", sub_matches)) => {
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

        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachable!()
    }

    Ok(())
}