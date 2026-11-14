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

The second source is `beagle.so` from the Beagle API (v6.00, macOS arm64), which Data Center
uses to talk to the analyzer. It was disassembled in Binary Ninja. It has no `.tdc` code at all
(no `TPDC` magic, no FastLZ, no container writer), so it says nothing about the file header,
the blocks or the record framing. What it does define is the per-packet and per-event data that
Data Center stores inside records: the read status word, the speed codes and the tick rate. See
[Beagle API correspondence](#beagle-api-correspondence) for what it settles and the addresses
behind each claim.

Each field below carries one of these labels:

* **Confirmed**: checked against an independent source. Usually that is the CSV export Data
  Center made of the same capture, which USBTraces has for
  `serial/ftdi/FT230X_Basic_UART_w7_init`, `net/nexus_5_ubuntu13_media_then_tether` and
  `bluetooth/iogear_gbu421_u13`. For those three files, every USB packet decoded from the
  `.tdc` matches the CSV export byte for byte, with the same timestamp to the microsecond
  (1,887, 2,634 and 135,134 packets). `tests/test_tdc.rs` checks this.
* **Structural**: the field's size and position are certain, because the reader walks all 31
  sample files end to end with no gaps or leftover bytes, but what the value means is a guess.
* **Confirmed (beagle.so)**: the meaning comes from the Beagle API binary and agrees with every
  sample that exercises it.
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
| 4 | u32 | unknown. It depends on the content: two identical captures in the set have the same value. It is not CRC-32, CRC-32C, Adler-32, FNV-1a or xxHash32 of either the compressed or decompressed data. `beagle.so` has no container code, so it cannot help here; Data Center itself would have to be disassembled | Unknown |
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
| 25 | u32 | tick rate in Hz, always 60,000,000 | Confirmed (timestamps match the CSV). It is the Beagle USB 480's sample clock: `beagle.so` sets 60,000 kHz for that model and for the USB 2 side of the USB 5000 family (48,000 kHz for the Beagle USB 12) |
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
| 0x00 | 4 bytes | **Status**, on every record. Byte 0: bits 0-2 are the speed (1 = low, 3 = full, 4 = high, 0 = none), bit 0x20 is the error flag. Bits 0x10 and 0x40 are described below the table. Byte 1 is unknown (0x10, 0x14, 0x28, 0x38 seen). Bytes 2-3 are a u16 device index, 0xFFFF for none | Speed LS/FS and the error bit confirmed against the CSV `Sp`/`Err` columns. HS = 4: Confirmed (beagle.so), see below |
| 0x01 | empty | Capture started | Confirmed |
| 0x02 | empty | Marks bus-level records (bus events, SOF groups) | Structural |
| 0x03 | 4 bytes | **Packet info**: `pid, kind, address, endpoint`. kind 0xFF = single packet, 0x01 = transaction. pid is the low nibble of the USB PID on packets, but on transactions its meaning is unknown. Endpoint bits 0-3 are the endpoint number and bit 4 is set for IN | Address, endpoint and PID confirmed |
| 0x04 | 4 bytes | Group info: 2 unknown bytes, then address and endpoint (same encoding as 0x03) | Address and endpoint confirmed |
| 0x05 | u32 count, u16 | Collapsed group count, e.g. `[6 IN-NAK]` | Confirmed |
| 0x06 | u32 count, u8, u8 flags, u16 first, u16 last | SOF group: `[31 SOF] Frames: 1012 - 1042`. Flags are 0x10 on SOF runs and 0x11 on low-speed keep-alive runs, whose frame numbers do not span the count (every low-speed sample, no full- or high-speed one) | Confirmed; flag meaning Structural |
| 0x07 | 11 or 15 bytes | Orphaned/unmatched group details | Unknown |
| 0x08, 0x09 | empty | Seen with 0x07 | Unknown |
| 0x0A | 5 bytes | Orphaned group: u32 count, u8 | Count confirmed |
| 0x0B | u32 status, u32 length, bytes | **The USB packet** as seen on the wire after SYNC and before EOP: PID byte, payload, CRC5/CRC16. Status is the Beagle API read status word (`BG_READ_*`, `BG_READ_USB_*`), stored unchanged. It is 0 on almost every packet | Packet bytes confirmed byte for byte. Status: Confirmed (beagle.so), see below |
| 0x0C | u8 kind, u8 n, n × u32 | **Transaction**: kind 0x0C SETUP, 0x03 IN, 0x07 OUT (others exist), then the child sequence numbers | Children confirmed. Kinds inferred from the CSV |
| 0x0F | u8 code, u32 status | **Bus event**. The code is Data Center's own (table below), not the API's `BG_EVENT_USB_*` bitmask. The status is the same API read status word as on packets: `BG_READ_TIMEOUT` (0x100) shows as `T` in the CSV `Err` column and `BG_READ_ERR_UNEXPECTED` (0x1000) as `U` | Codes in the table below confirmed against the three CSV exports. `T`/`U` confirmed; their identity with the API bits is inferred from the values |
| 0x11 | variable | List of child sequence numbers with an unknown prefix | Structural |
| 0x12, 0x13, 0x17 | empty | Flags with unknown meaning. 0x17 appears on most transactions in some captures | Unknown |
| 0x14, 0x16 | u32 count, u32 × n | Child sequence number lists (0x16 goes with SOF groups) | Structural |
| 0x15 | u32 n, n × UTF-16LE | **User comment** attached to a record | Confirmed (readable text) |

Common combinations: packet = `00 03 0B`, transaction = `00 03 0C [17]`, SOF group =
`00 02 06 [16]`, bus event = `00 02 0F`, collapsed NAKs = `00 04 05 [14]`.

#### Bus event codes

Each code is one row of the CSV export. Some rows name several line states at once.

| Code | CSV text | Confidence |
|---|---|---|
| 0x00 | `<Reset> / <Keep-alive> / <Target disconnected>` (low-speed bus) | Confirmed |
| 0x01 | `<Reset> / <Target disconnected>` | Confirmed |
| 0x04 | `<Reset> / <Chirp J> / <Tiny J>` | Confirmed |
| 0x07 | `<Host disconnected>` | Confirmed |
| 0x08 | `<Host connected>` | Confirmed |
| 0x0A | `<Low-speed>` | Confirmed |
| 0x0B | `<Full-speed>` | Confirmed |
| 0x0E | `<Suspend>` | Confirmed |
| 0x05 | Appears where full-speed captures have 0x04, but only on low-speed buses | Unknown |
| 0x0D | Thousands per capture on the high-speed samples, rare elsewhere. Probably high-speed related | Unknown |
| 0x02, 0x06, 0x13, 0x14 | Seen, mostly in hub captures | Unknown |

The earlier draft of this document read code 0x01 as "target disconnected" and 0x04 as "reset".
Lining the event records up against the CSV rows shows that each code stands for the whole row.

#### Status byte bits 0x10 and 0x40

These are Data Center's own and do not come from the API. Only co-occurrence is known:

* 0x10 is set on unmatched records: orphaned groups (elements `04 07 08` and `04 0A`), and a lone
  IN or NAK packet.
* 0x40 is set on SOF records: single SOF packets that failed their CRC check, and SOF groups in
  the hub captures `Linux_7port_numcheck`, `20140821_hub` and `20140823_current`. In
  `Linux_7port_numcheck`, 71,379 SOF groups carry 0x60 (0x40 plus the error bit) while their
  frame numbers are contiguous. These groups have no child list, so the packets behind the error
  flag cannot be checked. What the error flag means on SOF groups is not established.

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

## Beagle API correspondence

Addresses are in `ext/beagle-api-macos-arm64-v6.00/c/beagle.so` (Mach-O, arm64). The names are the
ones given in the Binary Ninja session. The exported `bg_*` functions are stubs: they look up the
device record with `bg_handle_to_device` (0x10518, 0x5440-byte records from 0x5c2e8), then jump
through a per-model function table. The open path, `bg_open_impl_install_vtable` (0x11504),
fills that table based on the top byte of the hardware id (`bg_device_type_ids`, 0x5c2b0):

| Id | Model (inferred) | `bg_usb_read` / `bg_usb2_read` | Sample clock |
|---|---|---|---|
| 0x42 | Beagle USB 12 | 0x16030 / 0x16cf4 | 48,000 kHz |
| 0x43 | Beagle USB 480 | `bg480_usb_read` 0x21f48 / `bg480_usb2_read` 0x220d4 | 60,000 kHz |
| 0x44, 0x46, 0x48 | Beagle USB 5000 family | 0x260b0 / 0x25ff4 | 60,000 kHz on the USB 2 side (500,000 kHz set for 0x44) |

### Read status word

`bg480_usb_parse_stream` (0x172a8) builds the status word that `bg_usb_read` returns, using the
bit values in `beagle.h`:

| Bit | Name | Set when |
|---|---|---|
| 0x0000_0100 | `BG_READ_TIMEOUT` | no data within the read timeout |
| 0x0000_1000 | `BG_READ_ERR_UNEXPECTED` | (value from `beagle.h`; the code that sets it was not traced) |
| 0x0001_0000 | `BG_READ_USB_ERR_BAD_SIGNALS` | hardware packet header bit 12 |
| 0x0020_0000 | `BG_READ_USB_ERR_BAD_PID` | the PID's check nibble is not the complement of its low nibble |
| 0x0040_0000 | `BG_READ_USB_ERR_BAD_CRC` | `usb_packet_crc_is_bad` (0x29bdc) fails |
| 0x2000_0000 | `BG_READ_USB_TRUNCATION_MODE` | hardware packet header bit 11 |
| 0x4000_0000 | `BG_READ_USB_END_OF_CAPTURE` | the analyzer's end-of-capture record |

`usb_packet_crc_is_bad` checks CRC5 on 3-byte packets, CRC5 on 4-byte SPLIT tokens (PID 0x78),
CRC16 on everything 4 bytes or longer, and nothing on packets shorter than 3 bytes.

The samples hold 17 packets with a non-zero status, in 7 files, with the values 0x1000, 0x10000,
0x200000, 0x210000, 0x400000 and 0x610000. All of them are made of the bits above, and the bytes
agree: every packet with a bad PID check nibble has 0x200000 and no other packet does, the six
4- and 5-byte SOFs in `20140821_hub` have 0x400000, and a 2-byte SOF fragment in
`20140823_current` has no CRC bit, as the binary predicts. `tests/test_tdc.rs` checks this.

### Speed codes

The analyzer reports bus speed in a type-0 hardware record (below). `bg480_usb_parse_stream`
maps its value 0 to 3, 1 to 1 and 2 to 4, and keeps that code at device offset 0x92a. A second
record kind produces code 2 together with a 3-bit port and 6 flag bits, on USB 5000 models only.
Data Center stores the same codes in the status element, so 1 = low, 3 = full, 4 = high. Code 2
has not been seen in a `.tdc`, and its meaning is unknown.

### Hardware stream (Beagle USB 480)

For reference, since it is what Data Center reads from the analyzer: `bg480_read_hw_record`
(0x1979c) reads the USB bulk-in stream as records that start with a little-endian u16 header.
The type is in `header >> 14`, and the base length is in `bg480_hw_record_len_by_type` (0x4f39c):

| Type | Length | Contents |
|---|---|---|
| 0 | 2 | Control. Bits 10-12 hold the subtype: header 0 = end of capture, 1 = idle tick, 2 = a timestamp record follows, 3 = speed or port information (USB 5000). Bit 13 marks a wrap of the 16-bit timestamp |
| 1 | 6 + n | Packet. Bits 0-10 hold the byte count n (padded to even), bit 11 = truncated, bit 12 = bad signals. Then u16 timestamp (low 16 bits), the packet bytes, and a u16 end timestamp |
| 2 | 4 | Event, with a u16 timestamp |
| 3 | 6 | Extended record. When bits 12-13 are 0x1000, a u16 timestamp and a u32 value follow; otherwise a u16 value and a u32 |

Timestamps carry only their low 16 bits, and the library keeps the high bits. Setting
`TP_BG5000_USB2_RAW_DUMP` makes the library write the raw stream to a file.

## Not covered

* High-speed specifics, such as split transactions, and the error flag on high-speed SOF groups.
  The HS speed code itself is now settled.
  There is no high-speed reference export to check against.
* Beagle 5000 (USB 3.0) captures. None are in the sample set. The packet status word would
  presumably carry the USB 3 `BG_READ_USB_*` bits from `beagle.h` (`PKT_TYPE_*`, `ERR_BAD_SLC_CRC_*`
  and so on), but the element tags they use are unknown.
* Writing `.tdc` files. That would need the block field at offset 4, which is still unknown.
