use anyhow::Result;
mod usb_request_block;
mod total_phase_csv_reader;
mod total_phase_parser;
mod pcap_writer;

use clap::{arg, Command};
use std::fs::File;
use std::io::BufWriter;
use crate::pcap_writer::PcapWriter;

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
            let filebase = sub_matches.get_one::<String>("FILE_BASE").expect("required");

            if filebase.ends_with(".csv") {
                let mut reader = total_phase_csv_reader::TotalPhaseCsvReader::new(filebase)?;
                let packets = reader.parse();
                for p in packets {
                    println!("{:?}", p);
                }
            } else {
                let packets = total_phase_parser::parse_totalphase_files(filebase)?;
                for p in packets {
                    println!("{:?}", p.dict_data());
                }
            }
        }

        Some(("pcap", sub_matches)) => {
            let filebase = sub_matches.get_one::<String>("FILE_BASE").expect("required");
            let output_path = sub_matches.get_one::<String>("OUTPUT").expect("required");

            let mut reader = total_phase_csv_reader::TotalPhaseCsvReader::new(filebase)?;
            let packets = reader.parse();

            let file = File::create(output_path)?;
            let writer = BufWriter::new(file);
            let mut pcap_writer = PcapWriter::new(writer)?;

            for p in packets {
                pcap_writer.write_urb(&p)?;
            }
        }

        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachable!()
    }

    Ok(())
}