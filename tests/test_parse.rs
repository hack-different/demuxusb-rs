#[cfg(test)]
mod tests {
    use super::*; // Bring the parent module's code into scope
    use demuxusb_rs::total_phase_parser;
    use std::fs;
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
}