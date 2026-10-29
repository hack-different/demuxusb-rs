//! Native reader for Total Phase Data Center capture files (`.tdc`).
//!
//! Total Phase does not publish this format. Everything here was reverse-engineered from the
//! captures in the USBTraces collection and checked against Data Center's own CSV/binary
//! exports of the same captures. See `docs/tdc-format.md` for the layout and for which fields
//! are confirmed and which are guesses.
//!
//! ```no_run
//! let file = demuxusb_rs::tdc::TdcFile::open("capture.tdc")?;
//! for record in file.records() {
//!     let record = record?;
//!     if let Some(bytes) = record.packet_data() {
//!         println!("{} {:02x?}", record.timestamp, bytes);
//!     }
//! }
//! # Ok::<(), demuxusb_rs::tdc::TdcError>(())
//! ```

pub mod fastlz;
pub mod pcap;
pub mod record;

pub use record::{Element, PacketInfo, Record, Speed, Status};

use std::fmt;
use std::path::Path;
use std::time::Duration;

pub const MAGIC: &[u8; 4] = b"TPDC";

/// Size of the `type, compressed length, unknown` prefix of each compressed block.
const BLOCK_HEADER_LEN: usize = 8;
/// Blocks decompress to this size, except the last one.
const BLOCK_SIZE: usize = 1 << 20;

const CAPTURE_ENTRY_KIND: u8 = 0x05;
const CAPTURE_ENTRY_FIXED_LEN: usize = 29;
const FOOTER_KIND: u8 = 0x06;

#[derive(Debug)]
pub enum TdcError {
    Io(std::io::Error),
    BadMagic([u8; 4]),
    /// The file ends inside a structure.
    Truncated {
        what: &'static str,
        offset: usize,
    },
    Decompress {
        block: usize,
        offset: usize,
        source: fastlz::FastLzError,
    },
    /// A structure in the decompressed stream does not have the expected shape.
    Corrupt {
        offset: usize,
        reason: String,
    },
}

impl fmt::Display for TdcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TdcError::Io(err) => write!(f, "I/O error: {err}"),
            TdcError::BadMagic(magic) => write!(f, "not a Data Center file (magic {magic:02x?})"),
            TdcError::Truncated { what, offset } => {
                write!(f, "file truncated in {what} at offset {offset:#x}")
            }
            TdcError::Decompress {
                block,
                offset,
                source,
            } => {
                write!(f, "block {block} at file offset {offset:#x}: {source}")
            }
            TdcError::Corrupt { offset, reason } => {
                write!(f, "stream offset {offset:#x}: {reason}")
            }
        }
    }
}

impl std::error::Error for TdcError {}

impl From<std::io::Error> for TdcError {
    fn from(err: std::io::Error) -> Self {
        TdcError::Io(err)
    }
}

/// One entry of the element-type table in the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementType {
    pub version: u16,
    pub tag: u8,
    pub kind: u8,
}

/// The uncompressed file header.
#[derive(Debug, Clone)]
pub struct Header {
    /// Bytes 4..6, always `00 03` so far.
    pub signature_version: [u8; 2],
    pub header_len: u16,
    /// Two u16s at 0x0c, plausibly the version and build of the Data Center release that wrote the file.
    pub writer_version: [u16; 2],
    /// Unix time the file was saved.
    pub saved_at: u32,
    /// Selects the size of capture-table entries. Seen: 0x107, 0x109, 0x10a.
    pub format_version: u16,
    /// The element types the record stream uses. The first entry (tag 0, kind 0) appears to
    /// describe the record itself.
    pub element_types: Vec<ElementType>,
    /// The whole header, for fields that are not decoded.
    pub raw: Vec<u8>,
}

/// One capture session. A file can hold several; Data Center shows the last one by default.
#[derive(Debug, Clone)]
pub struct Capture {
    /// 1-based; matches [`Record::capture`].
    pub id: u32,
    /// Always 3 so far, possibly the analyzer model.
    pub kind: u32,
    /// Unix time the capture started.
    pub started_at: u32,
    /// Unix time the capture stopped.
    pub stopped_at: u32,
    /// Length of the capture in analyzer ticks.
    pub duration_ticks: u64,
    /// Analyzer clock, 60 MHz in every sample.
    pub ticks_per_second: u32,
    /// Version-dependent trailing bytes that are not decoded.
    pub extra: Vec<u8>,
}

impl Capture {
    pub fn ticks_to_duration(&self, ticks: u64) -> Duration {
        let rate = self.ticks_per_second.max(1) as u128;
        Duration::from_nanos((ticks as u128 * 1_000_000_000 / rate) as u64)
    }

    /// Absolute wall-clock time of a record in this capture, as time since the Unix epoch.
    pub fn absolute_time(&self, ticks: u64) -> Duration {
        Duration::from_secs(self.started_at as u64) + self.ticks_to_duration(ticks)
    }
}

/// The trailing section after the last record. It holds the device table (descriptors and
/// string descriptors of enumerated devices) and per-capture statistics; it is kept raw.
#[derive(Debug, Clone)]
pub struct Footer {
    pub version: u32,
    pub data: Vec<u8>,
}

/// A fully decompressed .tdc file.
pub struct TdcFile {
    pub header: Header,
    pub captures: Vec<Capture>,
    pub footer: Option<Footer>,
    /// FastLZ level used by each block.
    pub block_levels: Vec<u8>,
    stream: Vec<u8>,
    records_start: usize,
    records_end: usize,
}

impl TdcFile {
    pub fn open(path: impl AsRef<Path>) -> Result<TdcFile, TdcError> {
        TdcFile::parse(&std::fs::read(path)?)
    }

    pub fn parse(bytes: &[u8]) -> Result<TdcFile, TdcError> {
        let header = parse_header(bytes)?;
        let (stream, block_levels) = decompress_blocks(bytes, header.header_len as usize)?;

        let mut offset = 0;
        let mut captures = Vec::new();
        while stream.get(offset) == Some(&CAPTURE_ENTRY_KIND) {
            let (capture, next) = parse_capture(&stream, offset, header.format_version)?;
            captures.push(capture);
            offset = next;
        }
        let records_start = offset;

        // Walk the record headers to find where the footer begins.
        while offset < stream.len() && stream[offset] != FOOTER_KIND {
            let length = stream
                .get(offset + 1..offset + 3)
                .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
                .ok_or(TdcError::Truncated {
                    what: "record header",
                    offset,
                })?;
            if length < record::RECORD_FIXED_LEN {
                return Err(TdcError::Corrupt {
                    offset,
                    reason: format!("record length {length} is too short"),
                });
            }
            offset += length;
        }
        if offset > stream.len() {
            return Err(TdcError::Truncated {
                what: "record",
                offset: stream.len(),
            });
        }
        let records_end = offset;
        let footer = parse_footer(&stream, offset)?;

        Ok(TdcFile {
            header,
            captures,
            footer,
            block_levels,
            stream,
            records_start,
            records_end,
        })
    }

    /// The decompressed stream (capture table, records and footer).
    pub fn stream(&self) -> &[u8] {
        &self.stream
    }

    pub fn records(&self) -> Records<'_> {
        Records {
            stream: &self.stream[..self.records_end],
            offset: self.records_start,
        }
    }

    pub fn capture(&self, id: u8) -> Option<&Capture> {
        self.captures.iter().find(|c| c.id == id as u32)
    }

    /// The capture Data Center shows when the file is opened.
    pub fn last_capture(&self) -> Option<&Capture> {
        self.captures.iter().max_by_key(|c| c.id)
    }
}

pub struct Records<'a> {
    stream: &'a [u8],
    offset: usize,
}

impl Iterator for Records<'_> {
    type Item = Result<Record, TdcError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.stream.len() {
            return None;
        }
        match Record::parse(self.stream, self.offset) {
            Ok((record, next)) => {
                self.offset = next;
                Some(Ok(record))
            }
            Err(err) => {
                self.offset = self.stream.len();
                Some(Err(err))
            }
        }
    }
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn parse_header(bytes: &[u8]) -> Result<Header, TdcError> {
    if bytes.len() < 0x28 {
        return Err(TdcError::Truncated {
            what: "file header",
            offset: bytes.len(),
        });
    }
    if &bytes[..4] != MAGIC {
        return Err(TdcError::BadMagic([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }
    let header_len = le_u16(bytes, 6);
    if bytes.len() < header_len as usize || (header_len as usize) < 0x28 {
        return Err(TdcError::Truncated {
            what: "file header",
            offset: bytes.len(),
        });
    }
    let raw = &bytes[..header_len as usize];

    let count = le_u16(raw, 0x26) as usize;
    let table = raw.get(0x28..0x28 + 4 * count).ok_or(TdcError::Truncated {
        what: "element type table",
        offset: 0x28,
    })?;
    let element_types = table
        .chunks_exact(4)
        .map(|e| ElementType {
            version: le_u16(e, 0),
            tag: e[2],
            kind: e[3],
        })
        .collect();

    Ok(Header {
        signature_version: [raw[4], raw[5]],
        header_len,
        writer_version: [le_u16(raw, 0x0c), le_u16(raw, 0x0e)],
        saved_at: le_u32(raw, 0x10),
        format_version: le_u16(raw, 0x14),
        element_types,
        raw: raw.to_vec(),
    })
}

fn decompress_blocks(bytes: &[u8], start: usize) -> Result<(Vec<u8>, Vec<u8>), TdcError> {
    let mut stream = Vec::new();
    let mut levels = Vec::new();
    let mut offset = start;
    while offset < bytes.len() {
        let header = bytes
            .get(offset..offset + BLOCK_HEADER_LEN)
            .ok_or(TdcError::Truncated {
                what: "block header",
                offset,
            })?;
        let compressed_len = u32::from_le_bytes([header[1], header[2], header[3], 0]) as usize;
        let payload = bytes
            .get(offset + BLOCK_HEADER_LEN..offset + BLOCK_HEADER_LEN + compressed_len)
            .ok_or(TdcError::Truncated {
                what: "block payload",
                offset,
            })?;
        let (block, level) =
            fastlz::decompress(payload, BLOCK_SIZE).map_err(|source| TdcError::Decompress {
                block: levels.len(),
                offset,
                source,
            })?;
        stream.extend_from_slice(&block);
        levels.push(level);
        offset += BLOCK_HEADER_LEN + compressed_len;
    }
    Ok((stream, levels))
}

/// Length of the undecoded tail of a capture-table entry, by header format version.
fn capture_extra_len(format_version: u16) -> Option<usize> {
    match format_version {
        0x107 => Some(14),
        0x109 => Some(15),
        0x10a => Some(16),
        _ => None,
    }
}

fn parse_capture(
    stream: &[u8],
    offset: usize,
    format_version: u16,
) -> Result<(Capture, usize), TdcError> {
    let fixed =
        stream
            .get(offset..offset + CAPTURE_ENTRY_FIXED_LEN)
            .ok_or(TdcError::Truncated {
                what: "capture table",
                offset,
            })?;
    let id = le_u32(fixed, 1);

    let extra_len = match capture_extra_len(format_version) {
        Some(len) => len,
        None => guess_capture_extra_len(stream, offset, id)
            .ok_or_else(|| TdcError::Corrupt {
                offset,
                reason: format!("unknown format version {format_version:#x} and could not find the end of the capture entry"),
            })?,
    };
    let end = offset + CAPTURE_ENTRY_FIXED_LEN + extra_len;
    let extra = stream
        .get(offset + CAPTURE_ENTRY_FIXED_LEN..end)
        .ok_or(TdcError::Truncated {
            what: "capture table",
            offset,
        })?;

    let mut duration = [0u8; 8];
    duration.copy_from_slice(&fixed[17..25]);
    Ok((
        Capture {
            id,
            kind: le_u32(fixed, 5),
            started_at: le_u32(fixed, 9),
            stopped_at: le_u32(fixed, 13),
            duration_ticks: u64::from_le_bytes(duration),
            ticks_per_second: le_u32(fixed, 25),
            extra: extra.to_vec(),
        },
        end,
    ))
}

/// For format versions we have not seen, find the entry's end by looking for what must follow
/// it: the next capture entry, or the first record (sequence number 0, reserved field 20).
fn guess_capture_extra_len(stream: &[u8], offset: usize, id: u32) -> Option<usize> {
    (8..=32).find(|extra| {
        let next = offset + CAPTURE_ENTRY_FIXED_LEN + extra;
        let Some(window) = stream.get(next..next + 16) else {
            return false;
        };
        let next_capture = window[0] == CAPTURE_ENTRY_KIND && le_u32(window, 1) == id + 1;
        let first_record = window[3] == 0
            && le_u16(window, 1) as usize >= record::RECORD_FIXED_LEN
            && le_u32(window, 4) == 0
            && le_u32(window, 12) == 20;
        next_capture || first_record
    })
}

fn parse_footer(stream: &[u8], offset: usize) -> Result<Option<Footer>, TdcError> {
    if offset >= stream.len() {
        return Ok(None);
    }
    let header = stream.get(offset..offset + 9).ok_or(TdcError::Truncated {
        what: "footer",
        offset,
    })?;
    let version = le_u32(header, 1);
    let length = le_u32(header, 5) as usize;
    let data = stream
        .get(offset + 9..offset + 9 + length)
        .ok_or(TdcError::Truncated {
            what: "footer",
            offset,
        })?;
    Ok(Some(Footer {
        version,
        data: data.to_vec(),
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Wraps an uncompressed stream in a .tdc container using literal-only FastLZ blocks.
    pub(crate) fn build_file(stream: &[u8]) -> Vec<u8> {
        let mut file = vec![0u8; 0x1a8];
        file[..4].copy_from_slice(MAGIC);
        file[4..6].copy_from_slice(&[0x00, 0x03]);
        file[6..8].copy_from_slice(&0x1a8u16.to_le_bytes());
        file[0x14..0x16].copy_from_slice(&0x10au16.to_le_bytes());
        file[0x26..0x28].copy_from_slice(&2u16.to_le_bytes());
        file[0x28..0x30].copy_from_slice(&[3, 0, 0, 0, 1, 0, 0x0b, 3]);

        for block in stream.chunks(BLOCK_SIZE) {
            let mut compressed = Vec::new();
            for literal in block.chunks(32) {
                compressed.push(literal.len() as u8 - 1);
                compressed.extend_from_slice(literal);
            }
            file.push(0);
            file.extend_from_slice(&(compressed.len() as u32).to_le_bytes()[..3]);
            file.extend_from_slice(&[0; 4]);
            file.extend_from_slice(&compressed);
        }
        file
    }

    fn capture_entry(id: u32) -> Vec<u8> {
        let mut entry = vec![CAPTURE_ENTRY_KIND];
        entry.extend_from_slice(&id.to_le_bytes());
        entry.extend_from_slice(&3u32.to_le_bytes());
        entry.extend_from_slice(&1_414_535_317u32.to_le_bytes());
        entry.extend_from_slice(&1_414_535_400u32.to_le_bytes());
        entry.extend_from_slice(&120_000_000u64.to_le_bytes());
        entry.extend_from_slice(&60_000_000u32.to_le_bytes());
        entry.extend_from_slice(&[0; 16]);
        entry
    }

    fn packet_record(sequence: u32, timestamp: u64, data: &[u8]) -> Vec<u8> {
        let mut elements = Vec::new();
        elements.extend_from_slice(&[0x00, 3, 10, 0, 0, 0, 0x03, 0, 0xff, 0xff]);
        let mut packet = vec![0x0b, 3];
        packet.extend_from_slice(&((14 + data.len()) as u32).to_le_bytes());
        packet.extend_from_slice(&0u32.to_le_bytes());
        packet.extend_from_slice(&(data.len() as u32).to_le_bytes());
        packet.extend_from_slice(data);
        elements.extend_from_slice(&packet);

        let mut record = vec![0x10];
        record.extend_from_slice(&((30 + elements.len()) as u16).to_le_bytes());
        record.push(0);
        record.extend_from_slice(&sequence.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&20u32.to_le_bytes());
        record.extend_from_slice(&[1, 0]);
        record.extend_from_slice(&timestamp.to_le_bytes());
        record.extend_from_slice(&45u32.to_le_bytes());
        record.extend_from_slice(&elements);
        record
    }

    #[test]
    fn round_trips_synthetic_file() {
        let mut stream = capture_entry(1);
        for i in 0..40_000u32 {
            stream.extend(packet_record(
                i,
                i as u64 * 60,
                &[0x69, (i & 0x7f) as u8, 0x10],
            ));
        }
        stream.extend_from_slice(&[FOOTER_KIND, 3, 0, 0, 0, 2, 0, 0, 0, 0xaa, 0xbb]);
        assert!(
            stream.len() > BLOCK_SIZE,
            "test should span more than one block"
        );

        let file = TdcFile::parse(&build_file(&stream)).unwrap();
        assert_eq!(file.header.format_version, 0x10a);
        assert_eq!(file.header.element_types.len(), 2);
        assert_eq!(file.block_levels.len(), stream.len().div_ceil(BLOCK_SIZE));
        assert_eq!(file.captures.len(), 1);
        assert_eq!(file.captures[0].ticks_per_second, 60_000_000);
        assert_eq!(file.footer.as_ref().unwrap().data, vec![0xaa, 0xbb]);

        let records: Vec<Record> = file.records().collect::<Result<_, _>>().unwrap();
        assert_eq!(records.len(), 40_000);
        assert_eq!(records[123].sequence, 123);
        assert_eq!(records[123].packet_data(), Some(&[0x69, 123, 0x10][..]));
        assert_eq!(
            file.captures[0].absolute_time(records[1000].timestamp),
            Duration::from_secs(1_414_535_317) + Duration::from_millis(1)
        );
    }

    #[test]
    fn guesses_capture_entry_size_for_unknown_versions() {
        let mut stream = capture_entry(1);
        stream.extend(capture_entry(2));
        stream.extend(packet_record(0, 0, &[0xd2]));
        let mut bytes = build_file(&stream);
        bytes[0x14..0x16].copy_from_slice(&0x1ffu16.to_le_bytes());

        let file = TdcFile::parse(&bytes).unwrap();
        assert_eq!(file.captures.len(), 2);
        assert_eq!(file.records().count(), 1);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = build_file(&capture_entry(1));
        bytes[0] = b'X';
        assert!(matches!(TdcFile::parse(&bytes), Err(TdcError::BadMagic(_))));
    }
}
