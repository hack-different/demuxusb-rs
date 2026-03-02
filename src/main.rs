mod usb_request_block;
mod total_phase_csv_reader;


use clap::{arg, Command};

fn cli() -> Command {
    Command::new("demuxusb-rs")
        .about("A fictional versioning CLI")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("info")
                .about("Reads and outputs info about USB stream")
                .arg(arg!(<FILE> "The stream file to read"))
                .arg_required_else_help(true),
        )
}

fn main() {
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("info", sub_matches)) => {
            let reader = total_phase_csv_reader::TotalPhaseCsvReader::new(
                sub_matches.get_one::<String>("FILE").expect("required")
            );
            let results = reader.expect("Must parse").parse();
            println!("Read {} rows", results.len());
        }

        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachable!()
    }

}