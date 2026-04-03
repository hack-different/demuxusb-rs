#[cfg(test)]
mod tests {
    // Bring the parent module's code into scope
    use demuxusb_rs::total_phase_parser;
    use std::fs;
    use std::fs::File;
    use std::io::BufWriter;
    use demuxusb_rs::pcap_writer::USBPcapWriter;

    #[test]
    fn parse_gbu421_u13() {
        let filebase = "ext/testdata/bluetooth/iogear_gbu421_u13";

        let mut reader = total_phase_parser::totalphase_reader(filebase).unwrap();
        let packets = reader.read();
    }

    #[test]
    fn parse_gbu421_u13_total_length() {
        let filebase = "ext/testdata/bluetooth/iogear_gbu421_u13";

        let mut reader = total_phase_parser::totalphase_reader(filebase).unwrap();
        let packets = reader.read();
        let total_len: u64 = packets.unwrap().iter().map(|p| p.length.unwrap_or(0)).sum();
        let metadata = fs::metadata(format!("{filebase}.bin")).unwrap();
        assert_eq!(metadata.len(), total_len as u64);
    }

    #[test]
    fn parse_gbu421_u13_pcap() {
        let filebase = "ext/testdata/bluetooth/iogear_gbu421_u13";
        let output_path = "ext/testdata/bluetooth/iogear_gbu421_u13.pcap";

        let mut reader = total_phase_parser::totalphase_reader(filebase).unwrap();
        let packets = reader.usb_request_blocks();

        let file = File::create(output_path).unwrap();
        let writer = BufWriter::new(file);
        let mut pcap_writer = USBPcapWriter::new(writer).unwrap();

        pcap_writer.write_urbs(&packets.unwrap()).expect("Conversion failed");
    }
}