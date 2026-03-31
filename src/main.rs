use anyhow::Result;
mod usb_request_block;
mod total_phase_csv_reader;
mod total_phase_parser;

use clap::{arg, Command};

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

        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachable!()
    }

    Ok(())
}