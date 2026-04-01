#[cfg(test)]
mod tests {
    use super::*; // Bring the parent module's code into scope
    use demuxusb_rs::total_phase_parser;
    #[test]
    fn parse_gbu421_u13() {
        let filebase = "ext/testdata/bluetooth/iogear_gbu421_u13";

        let mut reader = total_phase_parser::totalphase_reader(filebase).unwrap();
        let packets = reader.read();
    }
}