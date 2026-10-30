# Beagle USB analyzer wire protocol

This is how the Beagle API library (`beagle.so` v6.00, macOS arm64, in
`ext/beagle-api-macos-arm64-v6.00/c/`) talks to Total Phase Beagle USB analyzers. It was
reverse-engineered in Binary Ninja. The Rust driver in `src/beagle/` follows it. Function names are
the ones given in that Binary Ninja session, with their addresses.

**Status:** nothing here has been run against an analyzer yet. No device was attached while this
was written. Two parts are checked against real data: the packet CRC check agrees with the
analyzer's own verdict on every packet in the 31 `.tdc` samples, and the stream framing matches the
library's reader.

## Enumeration

`bg_enumerate_usb` (0xe87c) matches vendor 0x1679 with product 0x2001 or 0x2002. It also accepts an
unprogrammed Cypress FX2 (`04b4:00f3`) when the caller asks for it. For each device it records:

* **Firmware version**: bcdDevice turned into `major << 8 | minor`, with the minor part in decimal
  (bcd 0x0213 becomes 0x020d, version 2.13).
* **Unique id**: the decimal digits of the serial number string, read as one integer
  (`"1124-073472"` becomes 1124073472).

The top byte of the unique id selects the model. `bg_open_impl_install_vtable` (0x11504) installs a
per-model table of read functions on that basis:

| Top byte | Model | Sample clock | `SET_MODE` argument |
|---|---|---|---|
| 0x41 | I2C/SPI/MDIO Beagle | | 0 |
| 0x42 | Beagle USB 12 | 48 MHz | 1 |
| 0x43 | Beagle USB 480 | 60 MHz | 2 |
| 0x44 | Beagle USB 5000 | 60 MHz (USB 2) | 3 |
| 0x46, 0x48 | Beagle USB 5000 family | 60 MHz (USB 2) | 4 |
| 0x51 | not identified | | 5 |

The model names are inferred from the sample clocks and code paths.

## Firmware generations

* **1.00-1.99**: on every open, `bg_upload_firmware_v1` (0xd290) sends `PREPARE(1)` and then loads a
  RAM image into the FX2 with the standard Cypress vendor request 0xa0. It ends by writing CPUCS
  (0xe600) to release the 8051 (`fx2_load_ram_and_run`, 0xf63c). The image is stored XOR-scrambled
  inside `beagle.so`. A native driver would have to extract it from the user's own copy, since it
  is Total Phase's code and cannot ship with this project. Not implemented.
* **2.00-2.19**: on open, the library reads a 14-byte block with vendor request 0xb8 (bmRequestType
  0xc0, wValue 0, wIndex 0). Its contents are not decoded. `bg_upload_image_v2` (0xd170) assembles a
  separate image of 33 parts of up to 4 KiB, also scrambled. The Beagle USB 480 open path does not
  call it.

Other firmware versions are refused.

## Commands (EP 0x01 OUT, EP 0x81 IN)

`bg_cmd_roundtrip` (0xfd1c) writes a 64-byte packet to EP 0x01 and waits 50 ms. It then reads up to
1024 bytes from EP 0x81, waits 50 ms, and copies the first 64 bytes back over the command. A reply
shorter than 64 bytes is an error.

Packet layout: u16 opcode (little-endian) followed by arguments. One-byte results come back in byte
2.

| Opcode | Arguments | Use |
|---|---|---|
| 0x01 | mode | `SET_MODE` (`bg_cmd_set_mode`, 0xd460): the model, from the table above |
| 0x03 | 0 or 1 | `PREPARE` (`bg_cmd_prepare`, 0xd3d0): 1 before a firmware upload |
| 0x06 | 3 bytes | sent during open. The library sleeps 20 ms after it |
| 0x0e | | returns a byte (`bg_cmd_query_0e`, 0xdb24, kept at device offset 0x1e) |
| 0x14 | register, flags, length, data | register write (`bg_reg_write`, 0xe204) |
| 0x15 | | returns a byte (`bg_cmd_query_15`, 0xe498, kept at device offset 0x1f) |
| 0x1a | u16 length | firmware 2.x: sent before register writes of 60 bytes or more |
| 0x1b | 1, register | firmware 2.x register read (`bg_reg_read`, 0xe0a0). Firmware 1.x reads with opcode 0x14 and flags 1, 1 |

A register write carries up to 59 data bytes per packet, starting at byte 5. The flags byte is 3
when the data fits in one packet. Otherwise it is 1 on the first chunk, 0 on middle chunks and 2 on
the last. Only register 0 continues past the first chunk. Firmware 2.x renames register 0x51 to
0x50.

During open, the Beagle USB 480 is sent `QUERY_0E`, `SET_MODE(2)`, `PREPARE(1)`, `QUERY_15`,
`CONFIGURE` and `PREPARE(0)`. The library then reads the hardware version (0x11e6c, not traced) and
writes register 0x62 with 0x10 and then 0x18. The `bg_enable` and capture-configuration paths have
not been traced yet.

## Capture stream (EP 0x82 IN)

`bg_stream_read` (0x102f8) reads EP 0x82. `bg480_read_hw_record` (0x1979c) splits the bytes into
records that start with a little-endian u16 header. The record type is in the top two bits:

| Type | Length | Contents |
|---|---|---|
| 0 | 2 | Control. Bits 10-12 hold the subtype: an all-zero header ends the capture, 1 is an idle tick, 2 means a timestamp record follows, and 3 carries speed and port data (USB 5000 only). Bit 13 marks a wrap of the 16-bit timestamp |
| 1 | 6 + n | Packet. Bits 0-10 hold the byte count n (padded to even), bit 11 means truncated (the library then keeps at most 4 bytes), and bit 12 means bad signals. Then come a u16 timestamp, the packet bytes and a u16 end timestamp |
| 2 | 4 | Event, with a u16 timestamp |
| 3 | 6 | Extended record: a u16, then a u32. When bits 12-13 are 0x1000, the u16 is the timestamp |

Records carry only the low 16 bits of the 60 MHz timestamp, and the reader keeps the high bits. If
the environment variable `TP_BG5000_USB2_RAW_DUMP` names a file, the library appends every raw read
to it. That is the way to collect fixtures for this parser.

`bg480_usb_parse_stream` (0x172a8) builds API packets and their read status from these records.
See `docs/tdc-format.md` for the status bits and speed codes, and `src/beagle/stream.rs` for the CRC
rules (`usb_packet_crc_is_bad`, 0x29bdc).

## Next steps

1. Attach an analyzer and run `cargo run --example beagle -- info`. This checks enumeration, the
   0xb8 info block and the command round trip using read-only queries.
2. Trace `bg_enable`, `bg_usb2_capture_config` and `bg_disable` for the 480, following the call
   order in `python/capture_usb480.py`.
3. Record a raw dump with the vendor Python example. Check `cargo run --example beagle -- parse-dump`
   against the packets the example prints.
