# Total Phase Data Center `.tdc` capture format

This describes the file format that Total Phase Data Center uses to save USB captures from
Beagle protocol analyzers. The reader in `src/tdc/` implements it.

## Sources and confidence

Total Phase does not publish this format, and no open-source parser for it existed when this
was written. Their public material covers the analyzer API (the Beagle API, used to stream from
the hardware) and Data Center's CSV/binary *export*, not the saved file. Everything below was
reverse-engineered from the 31 captures in the
[USBTraces](https://github.com/rickmark/USBTraces) collection (a fork of `felis/USBTraces`),
written by Data Center releases that store header format versions 0x107, 0x109 and 0x10a.

Each field below carries one of these labels:

* **Confirmed**: checked against an independent source. Usually that is the CSV export Data
  Center made of the same capture, which USBTraces has for
  `serial/ftdi/FT230X_Basic_UART_w7_init`, `net/nexus_5_ubuntu13_media_then_tether` and
  `bluetooth/iogear_gbu421_u13`. For those three files, every USB packet decoded from the
  `.tdc` matches the CSV export byte for byte, with the same timestamp to the microsecond
  (1,887, 2,634 and 135,134 packets). `tests/test_tdc.rs` checks this.
* **Structural**: the field's size and position are certain, because the reader walks all 31
  sample files end to end with no gaps or leftover bytes, but what the value means is a guess.
* **Unknown**: present and preserved, meaning not established.

All integers are little-endian unless noted.

## Layout overview

```
+--------------------------+
| File header (uncompressed, header_len bytes)
+--------------------------+
| Block 0: 8-byte block header + FastLZ payload
| Block 1 ...
+--------------------------+

Concatenated decompressed blocks form one stream:

+--------------------------+
| Capture table: one entry per capture session
+--------------------------+
| Records, sequence numbers 0..N-1, in write order
+--------------------------+
| Footer: device table and statistics
+--------------------------+
```

## File header

| Offset | Size | Field | Notes | Confidence |
|---|---|---|---|---|
| 0x00 | 4 | magic | ASCII `TPDC` | Confirmed (all samples) |
| 0x04 | 2 | signature version | Always `00 03` | Unknown |
| 0x06 | u16 | header_len | Offset of the first block: 0x164 (format 0x107) or 0x1a8 | Structural |
| 0x08 | 4 | | Always 0 | Unknown |
| 0x0c | u16 ×2 | writer version | e.g. `1, 0x050e`, `3, 0x0634`, `5, 0x063d`. Probably the Data Center version and build | Unknown |
| 0x10 | u32 | saved_at | Unix time the file was saved. In the samples checked, it falls after the last capture's stop time | Structural |
| 0x14 | u16 | format_version | 0x107, 0x109 or 0x10a. Sets the size of capture-table entries | Structural |
| 0x16 | 10 | | e.g. `00 00 01 00 00 00 10 00 xx xx`. The last two bytes vary between files | Unknown |
| 0x20 | 6 | | | Unknown |
| 0x26 | u16 | element type count | Number of 4-byte entries that follow | Structural |
| 0x28 | 4 × count | element type table | Each entry is `u16 version, u8 tag, u8 kind`. The first entry is `3, 0x00, 0`, which seems to describe the record container. The rest are `1, tag, 3` for each element tag the stream uses | Structural |
| ... | | zero padding up to header_len | | Structural |

## Compressed blocks

The stream after the header is split into blocks:

| Offset | Size | Field | Confidence |
|---|---|---|---|
| 0 | u8 | block type, always 0 | Structural |
| 1 | u24 | compressed length (payload bytes after this 8-byte header) | Confirmed: the lengths chain exactly to end of file |
| 4 | u32 | unknown. It depends on the content: two identical captures in the set have the same value. It is not CRC-32, CRC-32C, Adler-32, FNV-1a or xxHash32 of either the compressed or decompressed data | Unknown |
| 8 | n | [FastLZ](https://github.com/ariya/FastLZ) payload | Confirmed |

Each block decompresses to exactly 1 MiB (1,048,576 bytes), except the last. Records cross block
boundaries freely, so the reader concatenates all blocks before parsing. FastLZ stores the
compression level in the top three bits of the first payload byte (`0` = level 1, `1` = level
2), and both levels show up in the samples.

## Capture table

A file can hold several capture sessions, for example when the user restarted a capture without
clearing it. Data Center shows, and exports, only the last one. The stream starts with one entry
per capture, each beginning with kind byte 0x05:

| Offset | Size | Field | Confidence |
|---|---|---|---|
| 0 | u8 | kind = 0x05 | Structural |
| 1 | u32 | capture id, 1-based and increasing. Matches the record's capture byte | Confirmed |
| 5 | u32 | always 3. Possibly the analyzer type | Unknown |
| 9 | u32 | start time, Unix seconds. Matches the CSV's `Capture started [...]` line | Confirmed |
| 13 | u32 | stop time, Unix seconds | Structural |
| 17 | u64 | capture duration in ticks. Equals (stop − start) to the second | Confirmed |
| 25 | u32 | tick rate in Hz, always 60,000,000 | Confirmed (timestamps match the CSV) |
| 29 | n | trailer: 14 bytes for format 0x107, 15 for 0x109, 16 for 0x10a. Typically `00 08 00 00 00 00 00 00 00 01 00 00 00 00 [00 00]` | Unknown |

For a format version not listed, the reader finds the end of each entry by looking ahead for the
next entry (kind 0x05, id + 1) or for the first record (sequence 0, reserved field 20).

## Records

After the capture table comes a run of records. A record starts with any byte other than 0x05
or 0x06, and a byte of 0x06 at a record boundary starts the footer.

| Offset | Size | Field | Notes | Confidence |
|---|---|---|---|---|
| 0 | u8 | flags | Bit 0x10 is set on top-level records. Captures other than the last also use 0x0a and 0x1a | Structural |
| 1 | u16 | length | Total record length, including these 4 bytes | Structural |
| 3 | u8 | always 0 | | Structural |
| 4 | u32 | sequence | Contiguous from 0 across the whole file. The CSV `Index` column is `sequence − first sequence of the exported capture` | Confirmed |
| 8 | u32 | nested | 1 for records that only exist as children of another record (the packets of a transaction, the packets inside an orphaned group); 0 otherwise. The CSV's deeper `Level` grouping (transfers made of transactions) is built by Data Center at display time and is not stored | Structural |
| 12 | u32 | always 20 | | Unknown |
| 16 | u8 | capture | Capture id from the capture table | Confirmed |
| 17 | u8 | capture flags | Usually 0. 0x03 on old captures, 0x10 on some transactions | Unknown |
| 18 | u64 | timestamp | Ticks since the start of the capture (60 MHz) | Confirmed |
| 26 | u32 | duration | Ticks | Confirmed |
| 30 | ... | elements | Until `length` | Structural |

Children are written *before* their parent, newest first. A transaction record lists the
sequence numbers of its token, data and handshake packets in reverse order. As a result,
records are not sorted by timestamp.

### Elements

Each element is `u8 tag, u8 kind (always 3), u32 length (including this 6-byte header), payload`.

| Tag | Payload | Meaning | Confidence |
|---|---|---|---|
| 0x00 | 4 bytes | **Status**, on every record. Byte 0: bits 0-2 are the speed (1 = low, 3 = full, 4 = high), bit 0x20 is the error flag. Bits 0x10/0x40 are set on some records, meaning unknown. Byte 1 is unknown. Bytes 2-3 are a u16 device index, 0xFFFF for none | Speed LS/FS and the error bit confirmed against the CSV `Sp`/`Err` columns. HS = 4 is inferred, since no reference export is high-speed |
| 0x01 | empty | Capture started | Confirmed |
| 0x02 | empty | Marks bus-level records (bus events, SOF groups) | Structural |
| 0x03 | 4 bytes | **Packet info**: `pid, kind, address, endpoint`. kind 0xFF = single packet, 0x01 = transaction. pid is the low nibble of the USB PID on packets, but on transactions its meaning is unknown. Endpoint bits 0-3 are the endpoint number and bit 4 is set for IN | Address, endpoint and PID confirmed |
| 0x04 | 4 bytes | Group info: 2 unknown bytes, then address and endpoint (same encoding as 0x03) | Address and endpoint confirmed |
| 0x05 | u32 count, u16 | Collapsed group count, e.g. `[6 IN-NAK]` | Confirmed |
| 0x06 | u32 count, u8, u8 flags, u16 first, u16 last | SOF group: `[31 SOF] Frames: 1012 - 1042` | Confirmed |
| 0x07 | 11 or 15 bytes | Orphaned/unmatched group details | Unknown |
| 0x08, 0x09 | empty | Seen with 0x07 | Unknown |
| 0x0A | 5 bytes | Orphaned group: u32 count, u8 | Count confirmed |
| 0x0B | u32 status, u32 length, bytes | **The USB packet** as seen on the wire after SYNC and before EOP: PID byte, payload, CRC5/CRC16. Status was 0 in every sample | Confirmed byte for byte |
| 0x0C | u8 kind, u8 n, n × u32 | **Transaction**: kind 0x0C SETUP, 0x03 IN, 0x07 OUT (others exist), then the child sequence numbers | Children confirmed. Kinds inferred from the CSV |
| 0x0F | u16 code, u8 flags, u16 | **Bus event**: 1 target disconnected, 4 reset, 7 host disconnected, 8 host connected, 0x0B speed detected (`<Full-speed>`), 0x0E suspend. Also seen: 0x05, 0x0A, 0x0D, 0x13, 0x14 | The listed codes confirmed |
| 0x11 | variable | List of child sequence numbers with an unknown prefix | Structural |
| 0x12, 0x13, 0x17 | empty | Flags with unknown meaning. 0x17 appears on most transactions in some captures | Unknown |
| 0x14, 0x16 | u32 count, u32 × n | Child sequence number lists (0x16 goes with SOF groups) | Structural |
| 0x15 | u32 n, n × UTF-16LE | **User comment** attached to a record | Confirmed (readable text) |

Common combinations: packet = `00 03 0B`, transaction = `00 03 0C [17]`, SOF group =
`00 02 06 [16]`, bus event = `00 02 0F`, collapsed NAKs = `00 04 05 [14]`.

## Footer

After the last record:

| Offset | Size | Field | Confidence |
|---|---|---|---|
| 0 | u8 | kind = 0x06 | Structural |
| 1 | u32 | version, always 3 | Unknown |
| 5 | u32 | length of the rest | Structural |
| 9 | n | device table and statistics | Unknown |

The footer holds a table of the devices seen on the bus. It includes their device and
configuration descriptors and their string descriptors as length-prefixed UTF-16LE (`<none>`,
`FT230X Basic UART`, `DB00FCX5`), plus per-endpoint counters. Record status elements refer
into it by device index. It is kept raw for now.

## Not covered

* High-speed specifics, such as split transactions and the meaning of the HS speed value.
  There is no high-speed reference export to check against.
* Beagle 5000 (USB 3.0) captures. None are in the sample set, and they will use other element tags.
* Writing `.tdc` files. That would need the block field at offset 4, which is still unknown.
