//! Checks the native .tdc reader against the captures in ext/testdata (the USBTraces collection).
//!
//! Three of those captures also have a CSV export made by Data Center itself. For those, every
//! packet the reader finds must appear in the CSV with the same bytes and the same timestamp
//! (to the microsecond, which is the CSV's resolution), and vice versa.

use demuxusb_rs::tdc::TdcFile;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const TESTDATA: &str = "ext/testdata";

fn testdata_present() -> bool {
    let present = Path::new(TESTDATA)
        .join("serial/ftdi/FT230X_Basic_UART_w7_init.tdc")
        .exists();
    if !present {
        eprintln!("skipping: {TESTDATA} is not checked out (git submodule update --init)");
    }
    present
}

fn tdc_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != ".git") {
                tdc_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "tdc") {
            out.push(path);
        }
    }
}

#[test]
fn every_sample_parses_completely() {
    if !testdata_present() {
        return;
    }
    let mut files = Vec::new();
    tdc_files(Path::new(TESTDATA), &mut files);
    assert!(
        files.len() >= 30,
        "expected the USBTraces captures, found {}",
        files.len()
    );

    for path in files {
        let file = TdcFile::open(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        assert!(!file.captures.is_empty(), "{}: no captures", path.display());
        assert!(file.footer.is_some(), "{}: no footer", path.display());

        let mut expected_sequence = 0;
        for record in file.records() {
            let record = record.unwrap_or_else(|err| panic!("{}: {err}", path.display()));
            assert_eq!(
                record.sequence,
                expected_sequence,
                "{}: sequence gap",
                path.display()
            );
            assert!(
                file.capture(record.capture).is_some(),
                "{}: unknown capture {}",
                path.display(),
                record.capture
            );
            assert!(
                record.status().is_some(),
                "{}: record {} has no status",
                path.display(),
                record.sequence
            );
            expected_sequence += 1;
        }
        assert!(expected_sequence > 0, "{}: no records", path.display());
    }
}

/// (microseconds since capture start, packet bytes) -> occurrences
type PacketSet = HashMap<(u64, Vec<u8>), usize>;

fn packets_from_csv(path: &Path) -> PacketSet {
    let reader = BufReader::new(fs::File::open(path).unwrap());
    let body: String = reader
        .lines()
        .map(|line| line.unwrap())
        .filter(|line| !line.starts_with('#'))
        .map(|line| line + "\n")
        .collect();

    let mut packets = PacketSet::new();
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(body.as_bytes());
    for row in csv.records() {
        let row = row.unwrap();
        // Level,Sp,Index,m:s.ms.us,Dur,Len,Err,Dev,Ep,Record,Data,Summary,ASCII
        if !row.get(9).unwrap_or("").trim_end().ends_with("packet") {
            continue;
        }
        let (minutes, rest) = row[3].split_once(':').unwrap();
        let parts: Vec<u64> = rest.split('.').map(|p| p.parse().unwrap()).collect();
        let micros =
            ((minutes.parse::<u64>().unwrap() * 60 + parts[0]) * 1000 + parts[1]) * 1000 + parts[2];
        let data = hex::decode(row[10].replace(' ', "")).unwrap();
        *packets.entry((micros, data)).or_default() += 1;
    }
    packets
}

fn packets_from_tdc(path: &Path) -> PacketSet {
    let file = TdcFile::open(path).unwrap();
    // Data Center exports the capture it shows, which is the last one in the file.
    let capture = file.last_capture().unwrap();
    let mut packets = PacketSet::new();
    for record in file.records() {
        let record = record.unwrap();
        if record.capture as u32 != capture.id {
            continue;
        }
        if let Some(data) = record.packet_data() {
            let micros = capture.ticks_to_duration(record.timestamp).as_micros() as u64;
            *packets.entry((micros, data.to_vec())).or_default() += 1;
        }
    }
    packets
}

fn assert_matches_csv_export(base: &str) {
    if !testdata_present() {
        return;
    }
    let base = Path::new(TESTDATA).join(base);
    let from_tdc = packets_from_tdc(&base.with_extension("tdc"));
    let from_csv = packets_from_csv(&base.with_extension("csv"));
    let count = |set: &PacketSet| set.values().sum::<usize>();
    assert!(count(&from_csv) > 0);
    assert_eq!(
        count(&from_tdc),
        count(&from_csv),
        "packet count differs from the CSV export"
    );
    assert_eq!(from_tdc, from_csv, "packets differ from the CSV export");
}

#[test]
fn ft230x_matches_csv_export() {
    assert_matches_csv_export("serial/ftdi/FT230X_Basic_UART_w7_init");
}

#[test]
fn nexus_5_matches_csv_export() {
    assert_matches_csv_export("net/nexus_5_ubuntu13_media_then_tether");
}

#[test]
fn gbu421_matches_csv_export() {
    assert_matches_csv_export("bluetooth/iogear_gbu421_u13");
}

#[test]
fn exports_pcapng() {
    if !testdata_present() {
        return;
    }
    let file = TdcFile::open(Path::new(TESTDATA).join("serial/ftdi/FT230X_Basic_UART_w7_init.tdc"))
        .unwrap();
    let mut out = Vec::new();
    let last = file.last_capture().unwrap().id as u8;
    let written = demuxusb_rs::tdc::pcap::write_pcapng(&file, Some(last), &mut out).unwrap();
    assert_eq!(written, 1887);
    assert!(out.len() > written * 32);
}
