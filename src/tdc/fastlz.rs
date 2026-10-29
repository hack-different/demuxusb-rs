//! FastLZ decompressor (levels 1 and 2).
//!
//! Data Center compresses each block of a .tdc file with FastLZ
//! (https://github.com/ariya/FastLZ). The compression level is carried in the top three bits
//! of the first byte of the stream, and both levels show up in real captures, so we support both.

use std::fmt;

/// Level 2 encodes far matches as `distance - MAX_L2_DISTANCE` in an extra 16 bit field.
const MAX_L2_DISTANCE: usize = 8191;

#[derive(Debug, PartialEq, Eq)]
pub enum FastLzError {
    Empty,
    UnknownLevel(u8),
    Truncated {
        input_offset: usize,
    },
    BadBackReference {
        input_offset: usize,
        distance: usize,
        output_len: usize,
    },
}

impl fmt::Display for FastLzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FastLzError::Empty => write!(f, "empty FastLZ stream"),
            FastLzError::UnknownLevel(level) => write!(f, "unknown FastLZ level {level}"),
            FastLzError::Truncated { input_offset } => {
                write!(f, "FastLZ stream truncated at input offset {input_offset}")
            }
            FastLzError::BadBackReference { input_offset, distance, output_len } => write!(
                f,
                "FastLZ back reference of distance {distance} with only {output_len} bytes of output (input offset {input_offset})"
            ),
        }
    }
}

impl std::error::Error for FastLzError {}

/// Decompresses a complete FastLZ stream, returning the output and the level it was written with.
///
/// `size_hint` is only used to pre-allocate; the output grows as needed.
pub fn decompress(input: &[u8], size_hint: usize) -> Result<(Vec<u8>, u8), FastLzError> {
    let first = *input.first().ok_or(FastLzError::Empty)?;
    let level = (first >> 5) + 1;
    if level > 2 {
        return Err(FastLzError::UnknownLevel(level));
    }

    let mut output = Vec::with_capacity(size_hint);
    let mut ip = 1;
    let mut ctrl = (first & 31) as usize;

    let next = |ip: &mut usize| -> Result<usize, FastLzError> {
        let byte = *input
            .get(*ip)
            .ok_or(FastLzError::Truncated { input_offset: *ip })?;
        *ip += 1;
        Ok(byte as usize)
    };

    loop {
        if ctrl >= 32 {
            // Back reference: length in the top three bits, high distance bits in the low five.
            let mut len = (ctrl >> 5) - 1;
            let high = (ctrl & 31) << 8;
            let mut distance;

            if level == 1 {
                if len == 6 {
                    len += next(&mut ip)?;
                }
                distance = high + next(&mut ip)?;
            } else {
                if len == 6 {
                    loop {
                        let code = next(&mut ip)?;
                        len += code;
                        if code != 255 {
                            break;
                        }
                    }
                }
                let code = next(&mut ip)?;
                distance = high + code;
                if code == 255 && high == (31 << 8) {
                    distance = (next(&mut ip)? << 8) + next(&mut ip)?;
                    distance += MAX_L2_DISTANCE;
                }
            }

            let len = len + 3;
            let distance = distance + 1;
            if distance > output.len() {
                return Err(FastLzError::BadBackReference {
                    input_offset: ip,
                    distance,
                    output_len: output.len(),
                });
            }
            // Matches may overlap the bytes they produce, so copy one byte at a time.
            let start = output.len() - distance;
            for i in 0..len {
                let byte = output[start + i];
                output.push(byte);
            }
        } else {
            let len = ctrl + 1;
            let literal = input
                .get(ip..ip + len)
                .ok_or(FastLzError::Truncated { input_offset: ip })?;
            output.extend_from_slice(literal);
            ip += len;
        }

        if ip >= input.len() {
            break;
        }
        ctrl = next(&mut ip)?;
    }

    Ok((output, level))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_run() {
        let (out, level) = decompress(&[0x02, b'a', b'b', b'c'], 0).unwrap();
        assert_eq!(out, b"abc");
        assert_eq!(level, 1);
    }

    #[test]
    fn level1_overlapping_match() {
        // "ab" then a match of length 6 at distance 2 -> "abababab"
        let input = [0x01, b'a', b'b', (4 << 5) | 0, 0x01];
        let (out, _) = decompress(&input, 0).unwrap();
        assert_eq!(out, b"abababab");
    }

    #[test]
    fn level1_long_match() {
        // len field 7 means "read one more length byte": 7 - 1 + 10 + 3 = 19 bytes of 'x'
        let input = [0x00, b'x', (7 << 5) | 0, 10, 0x00];
        let (out, _) = decompress(&input, 0).unwrap();
        assert_eq!(out, vec![b'x'; 20]);
    }

    #[test]
    fn level2_marker_and_long_length() {
        // Level 2 sets bit 5 of the first byte. Length bytes continue while they are 255.
        let input = [0x20 | 0x00, b'y', (7 << 5) | 0, 255, 1, 0x00];
        let (out, level) = decompress(&input, 0).unwrap();
        assert_eq!(level, 2);
        assert_eq!(out, vec![b'y'; 1 + 6 + 255 + 1 + 3]);
    }

    #[test]
    fn rejects_reference_before_start() {
        let input = [0x00, b'a', (1 << 5) | 0, 0x05];
        assert!(matches!(
            decompress(&input, 0),
            Err(FastLzError::BadBackReference { .. })
        ));
    }

    #[test]
    fn rejects_truncated_literal() {
        assert!(matches!(
            decompress(&[0x05, 1, 2], 0),
            Err(FastLzError::Truncated { .. })
        ));
    }
}
