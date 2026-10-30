# USB analyzer captures in pcapng: the USB TAP format

This specifies how a USB protocol-analyzer capture is stored in a pcapng file without losing
anything the analyzer recorded. The first source it covers is Total Phase Data Center `.tdc`
files (see [`tdc-format.md`](tdc-format.md)), but the encoding is written for any PHY-level USB
capture: USB 1.x/2.0 today, USB 3.x, USB4 and USB4 v2 as captures become available, and the
Power Delivery / Type-C CC side channel next to the data lines. It also defines how a PHY-level
capture is correlated with an OS-level capture of the same traffic (USBPcap, usbmon, macOS).

The `tdc-pcap` exporter in `src/tdc/pcap.rs` is the current state of the art in this repo, and
it will be replaced by an implementation of this document. Section
[What the current export loses](#what-the-current-export-loses) lists why.

Status of this document: **draft**. Nothing here has been assigned by IANA or tcpdump.org yet;
the placeholders are marked as such in [Placeholders](#placeholders).

## Sources and confidence

The TDC-side facts come from [`tdc-format.md`](tdc-format.md) as updated by the `beagle.so`
reversing work (PR #3) and keep that document's labels: **Confirmed**, **Structural**,
**Confirmed (beagle.so)** and **Unknown**. Fields marked Unknown are carried opaquely; when the
reversing effort assigns a meaning, the format does not change, only the reader's interpretation
of a byte string that is already preserved (see [Lossless round trip](#lossless-round-trip)).

The pcapng and link-type facts come from:

* The pcapng Internet-Draft, `draft-ietf-opsawg-pcapng-06` (September 2026):
  <https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcapng>. Sections cited: 3.5 options
  and padding, 4.2 IDB (`if_tsresol`, `if_tsoffset`), 4.3 EPB (`epb_flags`, `epb_packetid`,
  `epb_queue`, `epb_verdict`, `epb_processid_threadid`), 4.6 ISB, 4.8 Custom Block, 5 Custom
  Options.
* The link-type registry at <https://www.tcpdump.org/linktypes.html> (highest assigned value
  304, `LINKTYPE_DECT_NR_TAP`, at the time of writing) and the per-type pages
  `LINKTYPE_USB_2_0`, `LINKTYPE_USB_LINUX_MMAPPED`, `LINKTYPE_USB_DARWIN`. The IETF registry
  draft `draft-ietf-opsawg-pcaplinktype-08` lists the same USB values and the proposed
  allocation policy (0–32767 first-come first-served, 32768–65000 specification required,
  65001–65535 private use).
* The tcpdump-workers thread that added the per-speed USB 2.0 link types (Tomasz Moń, May 2022,
  <https://seclists.org/tcpdump/2022/q2/1>), whose stated problem was exactly that "the resulting
  pcap misses that information" about bus speed.
* Wireshark: the `usbll` dissector field reference
  (<https://wireshark.askapache.com/docs/dfref/u/usbll.html>), the 2019 commits adding the
  USB 2.0 link-layer dissector and its CRC5/CRC16 checks, and the custom block/option conventions
  Wireshark uses for itself (PEN 32622, <https://wiki.wireshark.org/Development/PcapngCustom>).
* USBPcap's capture format (<https://desowin.org/usbpcap/captureformat.html>), the OpenVizsla
  frame format (<https://github.com/matwey/libopenvizsla/wiki/OpenVizsla-protocol-description>,
  which also uses a 60 MHz tick counter), and the Chromium Twinkie USB-PD sniffer page
  (<https://www.chromium.org/chromium-os/developer-library/guides/hardware-schematics/twinkie>).

Each normative statement in this document is one of:

* **Normative**: implemented by the exporter and required of readers.
* **Provisional**: the encoding is fixed but the enumerations are expected to grow once real
  captures exist (USB 3.x, USB4, PD). Type codes are reserved; values are not final.
* **Open**: a decision the project owner has to make. Collected in
  [Open questions](#open-questions).

All integers in this document's own structures are little-endian regardless of the pcapng
section byte order; see [Conventions](#conventions).

## What the current export loses

`src/tdc/pcap.rs` writes one Enhanced Packet Block per TDC packet record on one of four
interfaces (`LINKTYPE_USB_2_0`, `_LOW_SPEED`, `_FULL_SPEED`, `_HIGH_SPEED`), with the packet
bytes as body and a nanosecond timestamp. Wireshark's `usbll` dissects the result. It drops:

| Lost | Where it was in the TDC |
|---|---|
| Exact 60 MHz ticks (the ns timestamp rounds every third tick) | record offset 18 |
| Packet duration | record offset 26 |
| The Beagle read status word: `BG_READ_TIMEOUT`, `BAD_PID`, `BAD_CRC`, `BAD_SIGNALS`, `TRUNCATION_MODE`, ... | element 0x0B status, element 0x0F status |
| Data Center's own status byte: error flag 0x20, bits 0x10/0x40, byte 1, device index | element 0x00 |
| Bus events: reset, chirp, connect/disconnect, speed detection, suspend, keep-alive | element 0x0F records (no EPB written) |
| Transactions, collapsed groups, SOF groups, orphan groups and their child lists | elements 0x0C, 0x05, 0x06, 0x0A, 0x07, 0x14, 0x16 (no EPB written) |
| Sequence numbers and nesting | record offsets 4 and 8 |
| Record flags, capture flags, the constant 20 | record offsets 0, 17, 12 |
| Capture sessions other than the one selected, their start/stop times and trailers | capture table |
| The device table and statistics | footer |
| The file header, element type table, block compression levels, block field at offset 4 | file header, block headers |
| User comments | element 0x15 |
| Any element the decoder does not understand (0x07, 0x08, 0x09, 0x11, 0x12, 0x13, 0x17, ...) | records |

## Survey of existing encodings

### USB link types

| Link type | Number | What a packet is | Verdict for this format |
|---|---|---|---|
| `LINKTYPE_USB_FREEBSD` | 186 | FreeBSD `usbdump` header (host byte order) + URB data | OS-level, host-order fields; not a PHY format |
| `LINKTYPE_USB_LINUX` | 189 | usbmon 48-byte header (host byte order) + URB data | OS-level |
| `LINKTYPE_USB_LINUX_MMAPPED` | 220 | usbmon 64-byte header (host byte order): URB id, event type S/C/E, transfer type, endpoint, device, bus, status, iso descriptors | OS-level. Used on the OS side of [correlation](#correlation-with-os-level-captures) |
| `LINKTYPE_USBPCAP` | 249 | 27-byte little-endian header: `irpId`, `USBD_STATUS`, URB function, bus, 16-bit device, endpoint, transfer type, plus control-stage / isochronous extensions | OS-level. The format page itself says it cannot describe speed or bus events. Correlation OS side |
| `LINKTYPE_USB_DARWIN` | 266 | Versioned (`0x0100`) little-endian header with explicit header length, request/complete type, status, unique id, `locationID`, endpoint speed 0–4 (LS to SuperSpeedPlus), address, endpoint, type | OS-level, but the only existing USB header with a version field, an explicit header length and a SuperSpeedPlus speed code. Correlation OS side |
| `LINKTYPE_OPENVIZSLA` | 278 | 8-byte header: magic 0xA0, 16-bit flags (PHY error, overflow, clipped, capture enabled/disabled), 16-bit size, 24-bit timestamp in 60 MHz FPGA cycles, then USB packet bytes | The closest PHY-level precedent. Fixed header, no speed, 24-bit wrapping tick counter. Shows the same 60 MHz exact-tick problem |
| `LINKTYPE_USB_2_0` | 288 | USB 2.0/1.1/1.0 packet "beginning with a PID" (PID, payload, CRC; no SYNC/EOP). Deprecated in favour of the per-speed types | The payload format this document uses for USB 2 wire bytes |
| `LINKTYPE_USB_2_0_LOW_SPEED` / `_FULL_SPEED` / `_HIGH_SPEED` | 293 / 294 / 295 | Same bytes, speed implied by the link type | What `tdc-pcap` writes today. Dissected by `usbll` |
| USB 3.x / SuperSpeed | none | No link type exists. `usbll` has no SuperSpeed fields (its field list ends at SPLIT and CRC checks). The 2018 wireshark-dev thread on link-layer dissection discusses transfer reassembly only | Must be defined here |
| USB4 | none | | Must be defined here |
| USB Power Delivery | none | Twinkie saves sigrok `.sr` files and decodes with libsigrokdecode's `usb_power_delivery`; Wireshark has no PD dissector and no link type. No vendor (Ellisys, Teledyne LeCroy, Total Phase) publishes a pcap export | Must be defined here |

Two things follow. First, every PHY-level precedent (288–295, 278) puts *no* metadata in the
packet except through the link-type number, and the one time metadata was needed (speed) the
registry grew by three entries. That does not scale to speeds, errors, durations, events and
USB 3/4/PD. Second, the TAP-style link types that the registry has adopted for other buses
(`LINKTYPE_IEEE802_15_4_TAP` 283, `LINKTYPE_ZWAVE_TAP` 297, `LINKTYPE_DECT_NR_TAP` 304) solve
the same problem with a versioned TLV pseudo-header in front of the wire bytes, and the registry
accepts such types. This document follows that pattern.

### pcapng mechanisms

| Mechanism | Fits | Notes |
|---|---|---|
| `if_tsresol` | partly | MSB 0: 10^-n; MSB 1: 2^-n. 60 MHz (period 50/3 ns) is neither, so no resolution makes ticks exact. See [Timestamps](#timestamps-and-clock-domains) |
| `if_tsoffset` | no | Seconds to add to every timestamp. It would carry the capture start time neatly, but reader support is uneven (the draft notes it; several readers ignore it). Not used; always 0. **Open** |
| `epb_flags` | yes | Direction bits 0–1 and the link-layer error bits 16–31 (bit 24 CRC error, 31 symbol error) are set when known, so standard tools can filter on them. The PHY-level detail stays in the pseudo-header |
| `epb_packetid` (code 5) | yes | 64-bit id "to correlate the same packet seen on multiple interfaces". Used for the analyzer sequence number and as the correlation key |
| `epb_queue`, `epb_verdict`, `epb_processid_threadid` | no | Host-side concepts; not used on PHY interfaces |
| `epb_dropcount` | partly | Could carry analyzer buffer-overflow counts if a source reports them. Reserved for that |
| Custom options 2988/2989 (copyable) and 19372/19373 (do not copy) | yes | `u16 type, u16 len, u32 PEN, data`. Used on the SHB and the IDBs for per-file and per-session information |
| Custom Block `0x00000BAD` (copyable) / `0x40000BAD` (do not copy) | yes | `u32 PEN` then custom data. Used for tables and correlation records, which have no timestamp and no interface |
| ISB | yes | `isb_starttime`/`isb_endtime`/`isb_ifrecv` carry the capture session's bounds and record count in a form every tool shows |
| NRB | no | Address-to-name records are IPv4/IPv6 only; a device table does not fit |
| DSB | no | Secrets; nothing to carry |
| Multiple SHB sections | no | A section is the unit of independent parsing; one `.tdc` file maps to one section. Sections are not used to separate capture sessions, because interface ids restart per section and correlation blocks need to address every interface in one id space |

## Design

### Two candidates

**A. TAP pseudo-header.** A new link type. Each EPB body is a versioned, TLV-based pseudo-header
followed by the raw link-layer bytes. All analyzer metadata is in the body.

**B. Native link types plus options.** EPBs use `LINKTYPE_USB_2_0_*`, the body is the raw bytes
only, and the metadata goes into a custom EPB option (2989 with PEN).

| | A: pseudo-header | B: options on `LINKTYPE_USB_2_0_*` |
|---|---|---|
| Works in Wireshark today | No: needs a dissector (small; it strips the header and calls `usbll`) | Yes for packets. Events and transactions have no link type and still need A |
| Survives `editcap`, `mergecap`, `tshark -w` | Yes: body is opaque data | Custom options are preserved only by tools that copy unknown options; the draft lets 19373 be dropped and even 2989 depends on the tool |
| Survives conversion to legacy `.pcap` | Yes | No: pcap has no options. All metadata lost |
| One interface per capture session | Yes; speed is per packet | No: one IDB per speed, and a bus that re-enumerates at another speed splits across interfaces |
| USB 3/4/PD payloads | Same mechanism, different `payload format` | No link type exists, so they need A anyway |
| Dissector access to metadata | One `tvb`, fields filterable (`usbtap.speed`) | Wireshark exposes custom options as raw bytes only |
| Size | ~130 bytes/packet of TLVs (see examples) | Same TLVs plus 8 bytes of option framing |

**Decision: A is the canonical encoding.** The argument that settles it is that B cannot carry
events, transactions, USB 3/4 or PD at all, so a B file would be a mixed file anyway, and the
remaining advantage (zero-day `usbll` support) is a Lua dissector of a few dozen lines that this
repo should ship. B is kept as an optional **compatibility profile** (see
[Profiles](#profiles)) with the *same* TLV bytes inside the option, so no second encoding exists.

### Shape of the format

```
pcapng section (one per source file)
|
+-- SHB            shb_userappl, custom: format version, file id
+-- CB  SOURCE_FILE            original container header, block table, hash   (once)
+-- IDB  session 1, channel USB        LINKTYPE_USB_TAP, custom: session info
+-- IDB  session 1, channel CC/PD      LINKTYPE_USB_TAP, custom: session info  (if present)
+-- IDB  session 2, channel USB        ...
+-- IDB  OS-level capture              LINKTYPE_USBPCAP / 220 / 266             (if merged)
+-- CB  DEVICE_TABLE                                                            (once per source)
+-- EPB  ...   one per analyzer record: packet, event, group, PD message, sample
+-- CB  CLOCK_MAP, CORRELATION, ADDRESS_MAP                                      (if correlated)
+-- ISB  one per IDB
```

Every analyzer record, whether or not it has wire bytes, is an EPB, because EPBs are the only
blocks with a timestamp and an interface, and the only ones that appear in a packet list. Tables
and cross-references are Custom Blocks. Per-session facts are IDB options. Per-file facts are
SHB options and one Custom Block.

## Conventions

* **Endianness.** pcapng block and option *framing* is in the section byte order, as the pcapng
  draft requires, and so is the PEN field of a custom block or option. Everything this document
  defines inside an EPB body, a custom option's data or a custom block's data is
  **little-endian**, always. The EPB body is opaque to pcapng and is never byte-swapped by
  tools, so it cannot depend on the section order; the option and block data follow the same
  rule so that one encoder serves all three places. Writers SHOULD write little-endian sections
  (`0x1A2B3C4D` as `4d 3c 2b 1a`) so that the two orders coincide.
* **Alignment.** Every structure is a sequence of 4-byte-aligned units. TLV headers are 4 bytes;
  TLV values are padded with zero bytes to a multiple of 4; the pseudo-header length is a
  multiple of 4. 64-bit fields are 4-byte aligned, not 8-byte aligned (same as pcapng).
  Readers MUST NOT assume 8-byte alignment.
* **TLV grammar** (used everywhere: pseudo-header, custom options, custom blocks):

  ```
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-------------------------------+-------------------------------+
  |            type (u16)         |    length (u16, value bytes)  |
  +-------------------------------+-------------------------------+
  |                     value, zero-padded to 4n                  |
  +---------------------------------------------------------------+
  ```

  `length` counts value bytes only, excluding padding. A value may itself be a TLV list
  (nested TLVs); the registry says which types nest. Types MAY repeat unless the registry says
  "once". Order is significant only where the registry says so (the TDC passthrough TLVs).
* **Unknown TLVs** MUST be skipped using `length`. A reader MUST NOT fail on an unknown type, an
  unknown enumeration value, or a value longer than it expects (extra bytes are future fields
  and are ignored). A value shorter than the reader expects is an error for that TLV only.
* **Versioning.** The pseudo-header carries a `version` byte; custom block and option data carry
  a `version` byte. Version 1 is this document. A reader that sees a higher version MUST still
  parse the TLV list (the grammar is frozen) and MAY ignore types it does not know. A version
  bump is reserved for a change to the fixed fields or the grammar, which this document intends
  never to need.
* **Strings** are UTF-8 without a terminator unless a TLV says otherwise.
* **Reserved fields** are written as zero and ignored on read.
* **Enumerations** are open: unlisted values are "unknown" and preserved.

### Type code registry ranges

The `type` space of the TLV grammar is partitioned once, for all three containers:

| Range | Use | Allocation |
|---|---|---|
| `0x0000` | reserved (never valid) | |
| `0x0001`–`0x0FFF` | core: timing, identity, generic USB, session, device table | this document |
| `0x1000`–`0x1FFF` | USB 1.x / 2.0 / eUSB2 specifics | this document |
| `0x2000`–`0x2FFF` | USB 3.x SuperSpeed / SuperSpeedPlus | this document (provisional) |
| `0x3000`–`0x3FFF` | USB4 and USB4 v2, including tunnelled protocols | this document (provisional) |
| `0x4000`–`0x4FFF` | Power Delivery / Type-C CC / VBUS / VCONN | this document (provisional) |
| `0x5000`–`0x5FFF` | correlation and clock domains | this document |
| `0x6000`–`0x6FFF` | reserved for future USB generations and other sidebands | unassigned |
| `0x7000`–`0x7FFF` | source-format passthrough, 256 codes per source format: `0x7000`–`0x70FF` TDC | this document |
| `0x8000`–`0xBFFF` | vendor: value begins with `u32 PEN`; the rest is vendor-defined | by PEN owner |
| `0xC000`–`0xEFFF` | experimental / private use; MUST NOT appear in interchange files | local |
| `0xF000`–`0xFFFF` | reserved | |

New codes in the document-owned ranges are added to this file in a PR that also adds a decoder.
A code is never reused once published, even if retired.

## Link type and pseudo-header

### Link type

The format needs one link type, **`LINKTYPE_USB_TAP`** (name provisional), to be requested from
tcpdump-workers (`tcpdump-workers@lists.tcpdump.org`) with this document as the specification.
Until it is assigned, writers use **`LINKTYPE_USER0` (147)** and readers MUST accept any of
147–162 when the IDB carries the `usbtap_if_info` custom option
([IDB options](#interface-description-block-one-per-session-and-channel)), which is the
authoritative marker. Wireshark maps DLT 147–162 to a dissector through
*Preferences → Protocols → DLT_USER*, which is how the dissector is attached before
assignment. See [Placeholders](#placeholders).

Everything on a USB TAP interface — USB 2 packets, USB 3 link-layer packets, PD messages, bus
events, transactions, analog samples — uses this one link type. What a packet *is* comes from
the pseudo-header, not from the link type number, so the registry never has to grow for a new
speed again.

### Pseudo-header layout

```
offset  size  field
0       u8    version      = 1
1       u8    record_kind  (table below)
2       u16   header_len   total pseudo-header length in bytes, including these 4, multiple of 4
4       ...   TLVs         until header_len
header_len    payload      link-layer bytes; absent for records that have none
```

The EPB `Captured Packet Length` and `Original Packet Length` both include the pseudo-header.
`Original Packet Length` differs from the captured length only when the analyzer truncated the
packet *and* reported the full length (`PAYLOAD_INFO.original_len`); otherwise they are equal
and truncation is signalled in `PAYLOAD_INFO.flags`.

| `record_kind` | Name | Payload | Meaning |
|---|---|---|---|
| 0x00 | reserved | | |
| 0x01 | `PACKET` | yes | One link-layer packet as seen on the wire |
| 0x02 | `EVENT` | no | A bus or analyzer state change (`EVENT` TLV required) |
| 0x03 | `GROUP` | no | A container the analyzer built: transaction, collapsed repeat, SOF run, orphan group (`GROUP_INFO` and usually `CHILDREN`) |
| 0x04 | `PD_MESSAGE` | yes | A USB PD message on a CC line (`PD_FRAME` required) |
| 0x05 | `CC_EVENT` | no | Termination / attach / orientation change on CC (`CC_STATE`) |
| 0x06 | `ANALOG_SAMPLE` | no | VBUS/VCONN/CC voltage and current (`POWER_SAMPLE`) |
| 0x07 | `MARKER` | no | Digital input change, trigger, user marker, comment-only record |
| 0x08 | `CAPTURE_CONTROL` | no | Capture started / stopped / end-of-capture |
| 0x09–0x7F | reserved | | |
| 0x80–0xFE | vendor | | Meaning given by a vendor TLV in the header |
| 0xFF | reserved | | |

`record_kind` is a hint for the dissector. A reader MUST be able to interpret the record from the
TLVs alone, and the TDC reconstruction ([Lossless round trip](#lossless-round-trip)) does not
look at it.

### Payload formats

`PAYLOAD_INFO.format` says what the bytes after the header are:

| Value | Name | Bytes |
|---|---|---|
| 0 | `USB2_PACKET` | Exactly what `LINKTYPE_USB_2_0*` carries: PID byte, payload, CRC5/CRC16. No SYNC, no EOP. Normative |
| 1 | `USB2_PACKET_WITH_SYNC` | As above but including SYNC bytes and any trailing EOP representation the analyzer gives. For analyzers that capture SYNC; the Beagle does not |
| 2 | `USB3_HEADER_PACKET` | 20 bytes: 12-byte header, CRC16, Link Control Word, after 8b/10b or 128b/132b decode and descrambling. LMP, TP, ITP. Provisional |
| 3 | `USB3_DATA_PACKET` | DPH (20 bytes) followed by DPP (data, CRC32) when the analyzer joins them. Provisional |
| 4 | `USB3_DATA_PAYLOAD` | DPP alone (when the analyzer records DPH and DPP separately). Provisional |
| 5 | `USB3_LINK_COMMAND` | 8 bytes (two copies of the link command word). Provisional |
| 6 | `USB3_ORDERED_SET` | Training sequence / SKP / other ordered set, as symbols decoded to bytes. Provisional |
| 7 | `USB4_TRANSPORT_PACKET` | USB4 transport-layer packet (header + payload + CRC) after descrambling; see `USB4_TRANSPORT`. Provisional |
| 8 | `PD_MESSAGE` | PD message as bytes after 4b5b decode: 16-bit header, data objects, (extended header), 32-bit CRC. Normative for PD |
| 9 | `PD_SYMBOLS` | 5-bit symbols packed MSB-first, including K-codes, before 4b5b decode. Provisional |
| 10 | `PHY_SYMBOLS` | Raw line symbols (10-bit or 132-bit groups) packed, before decode. Provisional |
| 11 | `USB4_SIDEBAND` | USB4 sideband (SBTX/SBRX) transaction bytes. Provisional |
| 12 | `USB4_ORDERED_SET` | USB4 ordered set / SLOS / TS as decoded bytes. Provisional |
| 0x80–0xFE | vendor | with a vendor TLV describing it |
| 0xFF | `OPAQUE` | Bytes with no further structure |

## TLV registry

Types marked **once** appear at most once per container. "Derived" means the TLV restates in a
generic form something a source-passthrough TLV also carries; derived TLVs are for readers and
are ignored by the round-trip reconstruction.

### Core (`0x0001`–`0x0FFF`)

| Type | Name | Value | Once | Meaning |
|---|---|---|---|---|
| `0x0001` | `TS_TICKS` | `u64` | once | Record start in analyzer ticks since the session epoch. The exact timestamp; the EPB timestamp is derived from it. Required on every TAP EPB |
| `0x0002` | `DURATION_TICKS` | `u64` | once | Record duration in ticks (packet: SOP to EOP; group: first to last child; event: 0 if instantaneous) |
| `0x0003` | `SPEED` | `u16 speed, u16 flags` | once | [Speed enumeration](#speed-enumeration). `flags`: bit 0 = speed was inferred by the writer rather than reported by the analyzer |
| `0x0004` | `DIRECTION` | `u8` | once | 0 unknown, 1 downstream (host to device), 2 upstream (device to host), 3 bus-wide / not applicable. Also mirrored into `epb_flags` bits 0–1 (upstream = inbound) |
| `0x0005` | `ERROR_FLAGS` | `u32` | once | [Generic error flags](#generic-error-flags). Derived from the source status where one exists; MAY be omitted when zero |
| `0x0006` | `EVENT` | `u16 event, u16 flags` | once | [Event enumeration](#event-enumeration). Required on `EVENT`, `CC_EVENT`, `CAPTURE_CONTROL` records |
| `0x0007` | `ADDRESS` | `u8 address, u8 endpoint, u8 hub_address, u8 hub_port` | once | USB device address and endpoint (bit 7 = IN, bits 0–3 = number, as in `bEndpointAddress`). `hub_address`/`hub_port` are for SPLIT tokens; 0xFF = not applicable. Derived on TDC |
| `0x0008` | `SEQUENCE` | `u64` | once | Analyzer-assigned record number, unique within the section. Same value as `epb_packetid`. Required |
| `0x0009` | `CHILDREN` | `n × u64` | | Sequence numbers of the records this group contains, in the order the analyzer stored them (TDC: newest first). Derived on TDC |
| `0x000A` | `GROUP_INFO` | `u8 kind, u8 subkind, u16 flags, u32 count, u32 first, u32 last` | once | `kind`: 1 transaction, 2 collapsed repeat (e.g. `[6 IN-NAK]`), 3 SOF run, 4 keep-alive run, 5 orphan/unmatched group, 6 transfer. `subkind`: for transactions the token PID (0x2D SETUP, 0x69 IN, 0xE1 OUT, 0xB4 PING, 0x78 SPLIT) or 0 if unknown; `count`: packets represented; `first`/`last`: frame numbers for SOF runs, else 0. Derived on TDC |
| `0x000B` | `COMMENT` | UTF-8 | | User comment attached to the record. Derived on TDC (from UTF-16LE) |
| `0x000C` | `DEVICE_REF` | `u32` | once | Index into the `DEVICE_TABLE` block of this section. Absent when the analyzer attached no device |
| `0x000D` | `SESSION` | `u32` | once | Capture session id, equal to the `SESSION` of the interface. Present on every EPB so that EPBs stay self-describing when interfaces are renumbered by a merge |
| `0x000E` | `HOST_TIME_NS` | `u64` | once | Host wall-clock time (ns since Unix epoch) the capturing software associated with the record, when the source has one separate from the analyzer clock |
| `0x000F` | `DIGITAL_IO` | `u8 inputs, u8 outputs, u8 changed_mask, u8 reserved` | once | Analyzer digital I/O pin states at the record |
| `0x0010` | `PAYLOAD_INFO` | `u8 format, u8 encoding, u8 flags, u8 reserved, u32 original_len` | once | `format`: [payload formats](#payload-formats). `encoding` of the line the bytes came from: 0 NRZI (USB 2), 1 8b/10b, 2 128b/132b, 3 BMC (PD), 4 PAM3 (USB4 Gen 4), 5 64b/66b (USB4 Gen 2/3). `flags`: bit 0 truncated by the analyzer, bit 1 payload is a fragment (SOP or EOP missing), bit 2 bytes were descrambled by the writer. `original_len`: full packet length when truncated and known, else 0. Required when a payload is present |
| `0x0011` | `ANALYZER_STATUS_RAW` | `u32` | once | The analyzer API's native per-record status word (for the Beagle: `BG_READ_*`). Mirrored from the source TLV so generic readers have it without knowing the source format. See [Beagle read status](#beagle-read-status-word) |
| `0x0012` | `FRAME_NUMBER` | `u32` | once | Frame or microframe number the record falls in, when the analyzer tracks it |
| `0x0013`–`0x001F` | reserved | | | |
| `0x0020` | `SESSION_START` | `u64` | once | Session epoch: Unix time in ns. IDB only |
| `0x0021` | `SESSION_STOP` | `u64` | once | Unix time in ns. IDB only |
| `0x0022` | `SESSION_DURATION_TICKS` | `u64` | once | IDB only |
| `0x0023` | `TICK_RATE` | `u64 numerator, u64 denominator` | once | Ticks per second as a rational: 60 MHz is `60000000 / 1`. Allows 48 MHz, 500 MHz, 1 THz or non-integer rates. IDB only; required |
| `0x0024` | `CHANNEL` | `u8` | once | 1 USB data lines (D+/D− or SSTX/SSRX lanes), 2 CC/PD, 3 VBUS/VCONN analog, 4 USB4 sideband, 5 digital I/O. IDB only; required |
| `0x0025` | `ANALYZER` | `u8 family, u8 model, u16 reserved, UTF-8 description` | once | Analyzer identity. `family`: 1 Total Phase Beagle (model: 1 USB 12, 2 USB 480, 3 USB 480 Power, 4 USB 5000 v1, 5 USB 5000 v2), 2 OpenVizsla, 3 LUNA/Cynthion, 4 Ellisys, 5 Teledyne LeCroy, 0xFF other. IDB only |
| `0x0026` | `INTERFACE_IDS` | `n × u32` | once | The other interface ids that belong to the same session (so a USB IDB points at its CC IDB and back). IDB only |
| `0x0027` | `ANALYZER_SERIAL` | UTF-8 | once | IDB only |
| `0x0028` | `SOFTWARE` | UTF-8 | once | Capturing software and version (e.g. `Data Center 6.73`). IDB or SHB |
| `0x0030` | `DEVICE_ENTRY` | nested TLVs | | One device of the device table: `DEVICE_INDEX`, `ADDRESS`, `SPEED`, descriptors, stats. `DEVICE_TABLE` block only |
| `0x0031` | `DEVICE_INDEX` | `u32` | once | The index `DEVICE_REF` points at |
| `0x0032` | `DESCRIPTOR` | `u8 bDescriptorType, u8 index, u16 wLangId, bytes` | | One descriptor as returned by the device: device (0x01), configuration (0x02, full `wTotalLength` bytes), string (0x03, raw UTF-16LE including `bLength`/`bDescriptorType`), BOS (0x0F), hub (0x29/0x2A), etc. `index`/`wLangId` as in the GET_DESCRIPTOR request, 0 when not applicable |
| `0x0033` | `ENDPOINT_STATS` | `u8 endpoint, u8 reserved[3], u64 packets, u64 bytes, u64 errors` | | Per-endpoint counters when the source keeps them |
| `0x0034` | `DEVICE_NAME` | UTF-8 | once | A name the capturing software gave the device |
| `0x0040` | `FORMAT_VERSION` | `u16 major, u16 minor` | once | This document's version (`1, 0`). SHB only |
| `0x0041` | `FILE_ID` | 16 bytes | once | Random UUID identifying this pcapng file for cross-file references. SHB only |
| `0x0042` | `SOURCE_NAME` | UTF-8 | once | Original file name. `SOURCE_FILE` block |
| `0x0043` | `SOURCE_HASH` | `u8 algorithm, u8 reserved[3], bytes` | | Hash of the original file: 1 SHA-256 (32 bytes), 2 BLAKE3 (32), 3 CRC-32 (4). `SOURCE_FILE` block |
| `0x0044` | `SOURCE_FORMAT` | `u16 format, u16 version` | once | 1 = Total Phase `.tdc` (version = `format_version` from the TDC header). `SOURCE_FILE` block |
| `0x0045` | `SEQUENCE_BASE` | `u64` | once | Added to every source record number to form `SEQUENCE`/`epb_packetid`; non-zero when several sources were merged into one section. `SOURCE_FILE` block |

### USB 1.x / 2.0 (`0x1000`–`0x1FFF`)

| Type | Name | Value | Meaning |
|---|---|---|---|
| `0x1000` | `USB2_LINE_STATE` | `u8 state, u8 reserved[3]` | Line state for events: 0 unknown, 1 SE0, 2 J, 3 K, 4 SE1, 5 chirp J, 6 chirp K, 7 idle (HS squelch) |
| `0x1001` | `USB2_SPLIT` | `u8 hub_address, u8 port, u8 flags, u8 endpoint_type` | Decoded SPLIT token fields when the analyzer provides them (otherwise `usbll` decodes the bytes). `flags`: bit 0 SC (complete), bit 1 S, bit 2 E/U |
| `0x1002` | `USB2_EOP_INFO` | `u32 eop_ticks, u8 flags, u8 reserved[3]` | EOP width in ticks and flags for false/long EOP as measured by analyzers that report it |
| `0x1003` | `EUSB2_INFO` | `u8 mode, u8 flags, u16 reserved` | eUSB2 repeater/native mode and control-message indication. Provisional |

### USB 3.x (`0x2000`–`0x2FFF`) — provisional

No USB 3 capture has been examined; these fix the slots and the shape so that a Beagle USB 5000
export does not need a new format. Values will be refined against real data.

| Type | Name | Value | Meaning |
|---|---|---|---|
| `0x2000` | `USB3_LINK_CONFIG` | `u8 generation, u8 lanes, u8 encoding, u8 flags` | `generation`: 1 Gen 1 (5 Gb/s), 2 Gen 2 (10 Gb/s). `lanes` 1 or 2. `encoding` as `PAYLOAD_INFO`. `flags`: bit 0 scrambling disabled |
| `0x2001` | `USB3_PACKET_TYPE` | `u8 type, u8 subtype, u16 reserved` | `type`: 1 LMP, 2 TP, 3 DPH, 4 DPP, 5 ITP, 6 link command, 7 ordered set, 8 LFPS, 9 logical idle / skip. `subtype`: LMP subtype, TP subtype (ACK, NRDY, ERDY, STATUS, STALL, DEV_NOTIFICATION, PING, PING_RESPONSE), link command (LGOOD_n, LCRD_x, LRTY, LBAD, LGO_Ux, LAU, LXU, LPMA, LUP, LDN), or ordered set (TSEQ, TS1, TS2, SKP, SDP, EDB, SLC, EPF, SYNC/SDS for SSP) |
| `0x2002` | `USB3_LANE` | `u8 lane, u8 direction, u16 reserved` | Physical lane the bytes were seen on; `direction` as `DIRECTION` |
| `0x2003` | `USB3_HEADER_SEQ` | `u8 header_seq, u8 flags, u16 reserved` | Header sequence number and the Deferred bit from the Link Control Word, when the analyzer decoded them |
| `0x2004` | `USB3_LFPS` | `u8 kind, u8 reserved[3], u32 burst_ticks, u32 repeat_ticks, u32 burst_count` | LFPS signalling: `kind` 1 Polling.LFPS, 2 Ping.LFPS, 3 U1 exit, 4 U2/U3 exit, 5 Warm Reset, 6 SCD1/SCD2 (SSP), 7 LBPM (SSP) |
| `0x2005` | `USB3_LTSSM` | `u8 from_state, u8 to_state, u16 reserved` | LTSSM transition; states: 1 SS.Disabled, 2 SS.Inactive, 3 Rx.Detect, 4 Polling, 5 U0, 6 U1, 7 U2, 8 U3, 9 Recovery, 10 Loopback, 11 Hot Reset, 12 Compliance Mode; 0x10–0x1F substates (Polling.LFPS, Polling.RxEQ, Polling.Active, Polling.Configuration, Polling.Idle, Recovery.Active, Recovery.Configuration, Recovery.Idle, ...). Also raised as `EVENT` 0x0100 + `to_state` |
| `0x2006` | `USB3_SYMBOL_ERRORS` | `u32 count, u32 flags` | 8b/10b or 128b/132b decode errors in this packet: bit 0 invalid symbol, bit 1 running disparity, bit 2 block header error, bit 3 framing |

### USB4 (`0x3000`–`0x3FFF`) — provisional

| Type | Name | Value | Meaning |
|---|---|---|---|
| `0x3000` | `USB4_LINK_CONFIG` | `u8 generation, u8 lanes_tx, u8 lanes_rx, u8 flags` | `generation`: 2 Gen 2 (10 Gb/s/lane), 3 Gen 3 (20), 4 Gen 4 (40; USB4 v2 80 Gb/s symmetric as 2+2 lanes, 120/40 asymmetric as 3+1). `flags`: bit 0 asymmetric, bit 1 TBT3-compatibility mode, bit 2 CL0s/CL1/CL2 low-power state active |
| `0x3001` | `USB4_LAYER` | `u8 layer, u8 reserved[3]` | 1 electrical/ordered set, 2 logical layer (SLOS, TS), 3 transport layer, 4 protocol adapter (tunnelled payload), 5 sideband channel, 6 control/Connection Manager |
| `0x3002` | `USB4_TRANSPORT` | `u8 pdf, u8 supp_id, u16 hop_id, u8 adapter_type, u8 adapter_num, u16 reserved, u32 flags` | Transport-layer routing: Protocol Defined Field, Supplemental ID, HopID; `adapter_type`: 1 USB3 tunnel, 2 PCIe tunnel, 3 DisplayPort IN, 4 DisplayPort OUT, 5 Host-to-Host, 6 control, 7 lane adapter. For tunnelled protocols the payload bytes are the tunnelled protocol's own packet (USB3 header/data packet, PCIe TLP/DLLP, DP main-link/AUX) and `PAYLOAD_INFO.format` names it |
| `0x3003` | `USB4_SIDEBAND` | `u8 kind, u8 flags, u16 reserved` | Sideband transaction: 1 AT (address/transaction), 2 LT, 3 LSE, 4 RT, 5 Broadcast; `flags`: bit 0 response |
| `0x3004` | `USB4_ROUTER` | `u64 route_string` | Topology ID of the router the packet is attributed to |
| `0x3005` | `USB4_LANE_STATE` | `u8 lane, u8 state, u16 reserved` | CLx / lane state transitions |

### Power Delivery and Type-C (`0x4000`–`0x4FFF`) — provisional

| Type | Name | Value | Meaning |
|---|---|---|---|
| `0x4000` | `PD_FRAME` | `u8 sop, u8 cc_line, u8 flags, u8 spec_rev, u32 goodcrc_ticks` | `sop`: 0 unknown, 1 SOP, 2 SOP', 3 SOP'', 4 SOP'_Debug, 5 SOP''_Debug, 6 Hard Reset, 7 Cable Reset, 8 undecodable (preamble/K-code error). `cc_line`: 0 unknown, 1 CC1, 2 CC2. `flags`: bit 0 CRC32 correct, bit 1 a GoodCRC was seen for this message, bit 2 this message *is* a GoodCRC, bit 3 preamble error, bit 4 K-code error, bit 5 retransmission, bit 6 extended message (PD 3.x), bit 7 EPR mode active. `spec_rev` as the header field: 0 PD 1.0, 1 PD 2.0, 2 PD 3.0/3.1/3.2; 0xFF unknown. `goodcrc_ticks`: ticks from end of this message to the start of its GoodCRC, 0 when none. Required on `PD_MESSAGE` |
| `0x4001` | `PD_RAW_BMC` | `u32 bit_count, u32 sample_rate_hz, bytes` | The BMC line bits of the whole frame (preamble through EOP) as sampled, packed LSB-first. Optional; lets a reader re-decode the line |
| `0x4002` | `PD_RAW_SYMBOLS` | `u32 symbol_count, bytes` | 5-bit symbols including K-codes (Sync-1/2/3, RST-1/2, EOP), packed MSB-first. Optional; alternative to payload format 9 when the decoded bytes are the payload |
| `0x4003` | `CC_STATE` | `u8 cc_line, u8 termination, u8 orientation, u8 role, u16 voltage_mv, u16 reserved` | `termination`: 0 open, 1 Rp default (USB power), 2 Rp 1.5 A, 3 Rp 3.0 A, 4 Rd, 5 Ra, 6 Rd+Ra, 7 Rp+Rd (attached), 0xFF unknown. `orientation`: 0 unknown, 1 CC1 is the active CC, 2 CC2. `role` (of the port being probed): 0 unknown, 1 Source/DFP, 2 Sink/UFP, 3 DRP toggling, 4 Debug accessory, 5 Audio accessory. Required on `CC_EVENT` |
| `0x4004` | `POWER_SAMPLE` | `u8 rail, u8 flags, u16 reserved, i32 voltage_uv, i32 current_ua` | `rail`: 1 VBUS, 2 VCONN, 3 CC1, 4 CC2, 5 SBU1, 6 SBU2. `flags`: bit 0 voltage valid, bit 1 current valid, bit 2 averaged over `DURATION_TICKS`, bit 3 current direction is source-to-sink positive |
| `0x4005` | `POWER_SAMPLE_RUN` | `u8 rail, u8 flags, u16 count, u32 interval_ticks, count × (i32 uv, i32 ua)` | A run of evenly spaced samples starting at `TS_TICKS`; for high-rate analog capture |
| `0x4006` | `PD_VDM_INFO` | `u16 svid, u8 command, u8 flags` | Derived from an unstructured/structured VDM header for quick filtering (Alt Mode: DisplayPort 0xFF01, Thunderbolt 0x8087, ...). Optional |

The PD message bytes themselves (header, data objects, extended header, CRC) are the payload,
format 8, so a dissector decodes Source_Capabilities, Request, VDMs, EPR, Alert and everything
else from the bytes, as libsigrokdecode does. The TAP header adds what the bytes cannot say:
which CC line, which SOP*, CRC and GoodCRC status, timing in the same tick domain as the data
lines, and the raw line symbols when the analyzer kept them.

### Correlation (`0x5000`–`0x5FFF`)

See [Correlation with OS-level captures](#correlation-with-os-level-captures) for how these are
used.

| Type | Name | Value | Meaning |
|---|---|---|---|
| `0x5000` | `CORR_OS_REF` | `PACKET_REF` body + `u8 method, u8 confidence, u16 reserved` | Inline on a TAP EPB: this PHY record realises the referenced OS-level record. Optional shortcut for a one-to-one match; the `CORRELATION` block is the general form |
| `0x5010` | `CLOCK_DOMAIN` | `u32 interface_id, u8 kind, u8 reserved[3], UTF-8 name` | Declares an interface's clock: `kind` 1 analyzer free-running oscillator, 2 host monotonic, 3 host wall clock, 4 PTP/NTP disciplined, 5 GPS |
| `0x5011` | `CLOCK_ANCHOR` | `u32 if_phy, u32 if_other, u64 phy_ticks, u64 other_time_ns, u32 uncertainty_ns, u8 method, u8 confidence, u16 reserved` | One observed simultaneity: PHY tick `phy_ticks` on `if_phy` corresponds to `other_time_ns` (ns since Unix epoch, or since that interface's own epoch if it has an `if_tsoffset`) on `if_other`. `method`: [clock methods](#clock-and-match-methods). `confidence` 0–255 |
| `0x5012` | `CLOCK_MODEL` | `u32 if_phy, u32 if_other, u64 ref_ticks, i64 offset_ps, i64 drift_ppb, u64 valid_from_ticks, u64 valid_to_ticks, u32 uncertainty_ps, u8 method, u8 confidence, u16 reserved` | A fitted linear model: `other_ns(t) = session_start_ns + t·10^9/rate + offset_ps/1000 + drift_ppb·10^-9·(t − ref_ticks)·10^9/rate`, valid for `valid_from_ticks ≤ t < valid_to_ticks` (`valid_to` = `0xFFFF_FFFF_FFFF_FFFF` means open). Several models MAY cover one pair for piecewise alignment |
| `0x5020` | `CORR_MATCH` | `u8 method, u8 confidence, u8 relation, u8 reserved, nested PACKET_REF × n` | One correlation: the referenced records (role 1 = OS side, role 2 = PHY side; at least one of each) describe the same traffic. `relation`: 1 OS transfer/URB realised by these PHY packets or transactions, 2 same packet observed on both, 3 OS control stage ↔ PHY SETUP/DATA/STATUS transactions, 4 partial (PHY side truncated or lost), 5 OS submit/complete pair ↔ PHY records |
| `0x5021` | `PACKET_REF` | `u8 ref_kind, u8 role, u16 reserved, u32 interface_id, u64 id, u64 id2` | A reference to one EPB. `ref_kind`: 1 `id` is `epb_packetid`; 2 `id` is the 0-based ordinal of the EPB among EPBs of `interface_id`; 3 `id`/`id2` are the native identifier of the OS header: USBPcap `irpId` and `info.direction`; usbmon URB id and event type (`'S'`, `'C'`, `'E'`); Darwin unique id and request type; TAP `SEQUENCE` and 0 |
| `0x5030` | `ADDRESS_BINDING` | `u32 if_phy, u32 if_os, u64 valid_from_ticks, u64 valid_to_ticks, u8 phy_address, u8 reserved, u16 os_bus, u16 os_device, u16 os_root_port, u32 os_location_id, u32 device_index, u8 method, u8 confidence, u16 reserved` | During `[valid_from, valid_to)` on the PHY interface, USB address `phy_address` is the device the OS capture calls bus `os_bus`, address `os_device` (USBPcap `bus`/`device`, usbmon bus/address), `os_location_id` (Darwin `locationID`; 0 if none), and `DEVICE_TABLE` entry `device_index` (0xFFFFFFFF if none). A device gets a new binding at every bus reset / SET_ADDRESS, which is how address reuse across resets is represented |
| `0x5040` | `FILE_REF` | `u8 role, u8 reserved[3], 16-byte file id, nested SOURCE_HASH / SOURCE_NAME` | Reference to another pcapng file that holds the other side of a correlation when both are not merged into one file. `role`: 1 OS-level capture, 2 PHY-level capture. The file id is that file's `FILE_ID` SHB option; the hash is the fallback when the file was rewritten |

#### Clock and match methods

| Value | `CLOCK_*` method | `CORR_MATCH` method |
|---|---|---|
| 0 | unknown | unknown |
| 1 | manual / user supplied | manual |
| 2 | single anchor (e.g. first packet aligned) | exact: identical payload bytes and ordering |
| 3 | linear regression over matched records | exact: shared hardware trigger or id (digital I/O pulse, host-stamped marker) |
| 4 | PTP/NTP disciplined clocks | heuristic: timing window + address/endpoint + length |
| 5 | GPS / PPS | heuristic: timing window only |
| 6 | hardware trigger line | inferred from another match (e.g. control stages from a matched SETUP) |

`confidence` is 0–255 with 255 meaning the writer treats the association as certain. Readers
SHOULD show it rather than hide low-confidence matches.

### Source passthrough: TDC (`0x7000`–`0x70FF`)

These carry the `.tdc` bytes that are not implied by the generic TLVs, so that the original
stream can be rebuilt byte for byte. Their order within a header is significant.

| Type | Name | Value | Once | Meaning |
|---|---|---|---|---|
| `0x7000` | `TDC_RECORD_HEADER` | `u8 flags, u8 byte3, u8 nested, u8 capture_flags, u32 reserved20` | once | Record offsets 0, 3, 8 (as 0/1), 17 and 12. Offsets 1–2 (length), 4 (sequence), 16 (capture), 18 (timestamp) and 26 (duration) are rebuilt from the TLV lengths, `SEQUENCE − SEQUENCE_BASE`, `SESSION`, `TS_TICKS` and `DURATION_TICKS`. Required on every EPB that came from a TDC record |
| `0x7001` | `TDC_ELEMENT` | `u8 tag, u8 kind, u16 reserved, payload` | | One element, verbatim payload, in stream order. Used for every element except the one `0x0B` whose bytes are the EPB payload |
| `0x7002` | `TDC_PACKET_ELEMENT` | `u8 tag (0x0B), u8 kind, u16 reserved, u32 status` | once | The packet element without its bytes: its `status` word (`BG_READ_*`) and position in the element order. Its `length` field and bytes are the EPB payload. If a record has more than one 0x0B element (never seen), all but the first are written as `TDC_ELEMENT` |
| `0x7003` | `TDC_RAW_RECORD` | bytes | once | A whole record that the writer could not parse into elements (corrupt length, bad element header). The EPB then has no payload and no other TDC TLV, and the generic TLVs come from the fixed header only |
| `0x7010` | `TDC_FILE_HEADER` | bytes | once | The uncompressed file header, `header_len` bytes verbatim (magic, versions, `saved_at`, element type table, padding). `SOURCE_FILE` block |
| `0x7011` | `TDC_BLOCK_TABLE` | `n × (u8 level, u8 type, u16 reserved, u32 unknown_at_4, u32 compressed_len, u32 decompressed_len)` | once | One entry per compressed block: FastLZ level, block type byte, the unknown u32 at block offset 4, and both lengths. `SOURCE_FILE` block. Needed to rebuild the *compressed* file; see [Lossless round trip](#lossless-round-trip) |
| `0x7020` | `TDC_CAPTURE_ENTRY_RAW` | bytes | once | One capture-table entry verbatim (29 fixed bytes plus the version-dependent trailer). On the session's IDB(s) |
| `0x7030` | `TDC_FOOTER_RAW` | `u32 version, bytes` | once | The footer after its kind byte and length: version field and the device table/statistics verbatim. `DEVICE_TABLE` block |
| `0x7031` | `TDC_STREAM_TAIL` | bytes | once | Any bytes after the footer in the decompressed stream (none seen). `DEVICE_TABLE` block |

### Vendor (`0x8000`–`0xBFFF`)

Value is `u32 PEN` followed by vendor-defined bytes. The PEN owner keeps the registry for the
types it uses; a type code is unique per PEN, so two vendors may use the same code.

## Enumerations

### Speed enumeration

`SPEED.speed` (u16). Grouped by generation; gaps are for additions.

| Value | Name | Rate |
|---|---|---|
| `0x0000` | unknown | |
| `0x0001` | `LOW` | 1.5 Mb/s |
| `0x0002` | `FULL` | 12 Mb/s |
| `0x0003` | `HIGH` | 480 Mb/s |
| `0x0004` | `LOW_OVER_FULL` | low-speed packets with full-speed preamble (PRE) on a full-speed bus |
| `0x0008` | `EUSB2_FULL` | eUSB2 full-speed signalling |
| `0x0009` | `EUSB2_HIGH` | eUSB2 high-speed signalling |
| `0x0010` | `SS_GEN1X1` | 5 Gb/s (USB 3.0 / 3.1 Gen 1 / 3.2 Gen 1x1) |
| `0x0011` | `SS_GEN2X1` | 10 Gb/s (3.1 Gen 2 / 3.2 Gen 2x1) |
| `0x0012` | `SS_GEN1X2` | 10 Gb/s (3.2 Gen 1x2) |
| `0x0013` | `SS_GEN2X2` | 20 Gb/s (3.2 Gen 2x2) |
| `0x0020` | `USB4_GEN2X1` | 10 Gb/s |
| `0x0021` | `USB4_GEN2X2` | 20 Gb/s |
| `0x0022` | `USB4_GEN3X1` | 20 Gb/s |
| `0x0023` | `USB4_GEN3X2` | 40 Gb/s |
| `0x0024` | `USB4_GEN4_SYM` | 80 Gb/s (USB4 v2, 2 + 2 lanes) |
| `0x0025` | `USB4_GEN4_ASYM_TX` | 120 Gb/s down / 40 Gb/s up (3 + 1) |
| `0x0026` | `USB4_GEN4_ASYM_RX` | 40 Gb/s down / 120 Gb/s up (1 + 3) |
| `0x0030` | `TBT3_GEN2` | Thunderbolt 3 compatibility, 10 Gb/s/lane |
| `0x0031` | `TBT3_GEN3` | Thunderbolt 3 compatibility, 20 Gb/s/lane |
| `0x0040` | `PD_BMC` | PD on CC, BMC, 300 kb/s |
| `0x0041` | `PD_FSK` | PD 1.0 FSK on VBUS (historical) |
| `0x0042` | `USB4_SIDEBAND` | USB4 sideband channel, 1 Mb/s |
| `0x0100`–`0x7FFF` | reserved | |
| `0x8000`–`0xFFFF` | vendor / source-native code (see `TDC_ELEMENT` 0x00 for the Beagle's own 1/3/4) | |

Beagle status codes map as 1 → `LOW`, 3 → `FULL`, 4 → `HIGH` (Confirmed (beagle.so)), 0 →
unknown (the TLV is omitted), 2 → `0x8002` (seen in the API for USB 5000 port records, never in a
`.tdc`, meaning unknown).

### Event enumeration

`EVENT.event` (u16). `EVENT.flags` bit 0 = the event is the *end* of the named condition
(e.g. reset released) rather than its start, for analyzers that report both edges.

| Value | Name | Notes |
|---|---|---|
| `0x0000` | unknown | Source-specific code is in the passthrough TLV |
| `0x0001` | `BUS_RESET` | SE0 longer than the reset threshold |
| `0x0002` | `HOST_CONNECT` | |
| `0x0003` | `HOST_DISCONNECT` | |
| `0x0004` | `TARGET_CONNECT` | |
| `0x0005` | `TARGET_DISCONNECT` | |
| `0x0006` | `SPEED_DETECTED` | The speed is in the `SPEED` TLV of the same record |
| `0x0007` | `SUSPEND` | |
| `0x0008` | `RESUME` | |
| `0x0009` | `KEEP_ALIVE` | Low-speed keep-alive EOP |
| `0x000A` | `CHIRP_J` | |
| `0x000B` | `CHIRP_K` | |
| `0x000C` | `TINY_J` | |
| `0x000D` | `VBUS_PRESENT` | |
| `0x000E` | `VBUS_ABSENT` | |
| `0x000F` | `DIGITAL_INPUT` | Pin states in `DIGITAL_IO` |
| `0x0010` | `TRIGGER` | Analyzer trigger fired |
| `0x0011` | `CAPTURE_START` | First record of a session (TDC element 0x01) |
| `0x0012` | `CAPTURE_STOP` | Last record / end-of-capture marker |
| `0x0013` | `OVERFLOW` | Analyzer buffer overflow; `epb_dropcount` MAY carry the count |
| `0x0014` | `OTG_SRP` | |
| `0x0015` | `OTG_HNP` | |
| `0x0016` | `LINE_STATE` | Generic line-state change; details in `USB2_LINE_STATE` |
| `0x0100`–`0x01FF` | `LTSSM_<state>` | USB 3 LTSSM entered state `event & 0xFF` (states as in `USB3_LTSSM`) |
| `0x0200`–`0x02FF` | USB4 link events | `0x0200` lane adapter enabled, `0x0201` CL state change, `0x0202` sideband link up, `0x0203` router enumerated. Provisional |
| `0x0300`–`0x03FF` | Type-C events | `0x0300` attached as Source, `0x0301` attached as Sink, `0x0302` detached, `0x0303` orientation change, `0x0304` VCONN on, `0x0305` VCONN off, `0x0306` debug accessory, `0x0307` audio accessory, `0x0308` PD Hard Reset seen, `0x0309` PD Cable Reset seen, `0x030A` power role swap, `0x030B` data role swap. Provisional |
| `0x8000`–`0xFFFF` | vendor / source-native | The code is in the passthrough TLV; the generic value is unknown |

Data Center's bus-event codes (TDC element 0x0F, Confirmed) name several line states in one
row, so the mapping to a single generic event is lossy on purpose and the code itself is kept in
the `TDC_ELEMENT`:

| TDC code | CSV text | Generic `EVENT` |
|---|---|---|
| 0x00 | `<Reset> / <Keep-alive> / <Target disconnected>` | `BUS_RESET`, flags bit 8 set ("compound; see source code") |
| 0x01 | `<Reset> / <Target disconnected>` | `BUS_RESET`, flags bit 8 |
| 0x04 | `<Reset> / <Chirp J> / <Tiny J>` | `BUS_RESET`, flags bit 8 |
| 0x07 | `<Host disconnected>` | `HOST_DISCONNECT` |
| 0x08 | `<Host connected>` | `HOST_CONNECT` |
| 0x0A | `<Low-speed>` | `SPEED_DETECTED` + `SPEED` = `LOW` |
| 0x0B | `<Full-speed>` | `SPEED_DETECTED` + `SPEED` = `FULL` |
| 0x0E | `<Suspend>` | `SUSPEND` |
| 0x05, 0x0D, 0x02, 0x06, 0x13, 0x14 | unknown | `0x8000 + code` |

`EVENT.flags` bit 8 means "the source names more than one condition; consult the source TLV".

### Generic error flags

`ERROR_FLAGS` (u32). Bits 0–15 are link-layer conditions, 16–23 analyzer conditions, 24–30 PD,
31 "flagged by the capturing software without further detail".

| Bit | Name | Beagle source (`BG_READ_*`, Confirmed (beagle.so) unless noted) |
|---|---|---|
| 0 | `CRC_ERROR` | `USB_ERR_BAD_CRC` 0x0040_0000 |
| 1 | `BAD_PID` | `USB_ERR_BAD_PID` 0x0020_0000 |
| 2 | `BIT_STUFF` | `USB_ERR_BIT_STUFF` 0x0004_0000 (value from `beagle.h`) |
| 3 | `BAD_SYNC` | `USB_ERR_BAD_SYNC` 0x0002_0000 (value from `beagle.h`) |
| 4 | `FALSE_EOP` | `USB_ERR_FALSE_EOP` 0x0008_0000 (value from `beagle.h`) |
| 5 | `LONG_EOP` | `USB_ERR_LONG_EOP` 0x0010_0000 (value from `beagle.h`) |
| 6 | `BAD_SIGNALS` | `USB_ERR_BAD_SIGNALS` 0x0001_0000 |
| 7 | `TRUNCATED` | `USB_TRUNCATION_MODE` 0x2000_0000 (truncation length in bits 0–7 of the status word is kept in the raw word) |
| 8 | `SYMBOL_ERROR` | USB 3/4 decode error; also `epb_flags` bit 31 |
| 9 | `DISPARITY_ERROR` | |
| 10 | `FRAMING_ERROR` | |
| 11 | `LCW_CRC5_ERROR` | USB 3 Link Control Word |
| 12 | `HEADER_CRC16_ERROR` | USB 3 header packet |
| 13 | `DATA_CRC32_ERROR` | USB 3 data packet payload |
| 16 | `TIMEOUT` | `TIMEOUT` 0x0000_0100 (CSV `Err` = `T`) |
| 17 | `MIDDLE_OF_PACKET` | `ERR_MIDDLE_OF_PACKET` 0x0000_0200 |
| 18 | `SHORT_BUFFER` | `ERR_SHORT_BUFFER` 0x0000_0400 |
| 19 | `PARTIAL_LAST_BYTE` | `ERR_PARTIAL_LAST_BYTE` 0x0000_0800 |
| 20 | `UNEXPECTED` | `ERR_UNEXPECTED` 0x0000_1000 (CSV `Err` = `U`) |
| 21 | `END_OF_CAPTURE` | `USB_END_OF_CAPTURE` 0x4000_0000 |
| 22 | `OVERFLOW` | |
| 24 | `PD_CRC32_ERROR` | |
| 25 | `PD_PREAMBLE_ERROR` | |
| 26 | `PD_KCODE_ERROR` | |
| 27 | `PD_NO_GOODCRC` | |
| 31 | `SOFTWARE_FLAGGED` | TDC status element byte 0 bit 0x20 (CSV `Err` column, Confirmed) |

Any Beagle status bit not in this table stays in `ANALYZER_STATUS_RAW` and the `TDC_ELEMENT`;
`ERROR_FLAGS` is a derived view.

#### Beagle read status word

For reference, the word carried in `ANALYZER_STATUS_RAW` / `TDC_PACKET_ELEMENT.status` /
`TDC_ELEMENT` 0x0F for Beagle sources is the Beagle API's `bg_usb*_read` status. The bits above
0x0100 are listed in the table; bits 0–7 hold the truncation length when `USB_TRUNCATION_MODE` is
set (from `beagle.h`; not exercised by any sample). USB 3 bits (`PKT_TYPE_*`, `ERR_BAD_SLC_CRC_*`,
...) exist in `beagle.h` and will be mapped into bits 8–13 above once a Beagle 5000 capture is
examined. **Open.**

## pcapng container mapping

### Section Header Block (one per source file)

| Option | Value |
|---|---|
| `shb_hardware` | analyzer model and serial if known (`Total Phase Beagle USB 480`) |
| `shb_os` | omitted (the analyzer has none); for merged OS captures, that section's own |
| `shb_userappl` | `demuxusb-rs tdc-pcapng <version>` |
| custom 2989, PEN, subtype 1 (`usbtap_file`) | TLVs `FORMAT_VERSION`, `FILE_ID`, `SOFTWARE`. Required |

### `SOURCE_FILE` custom block (one per source file, before the first IDB)

Custom Block `0x00000BAD` (copyable), data = [custom block header](#custom-block-data-layout)
subtype 2, TLVs `SOURCE_FORMAT`, `SOURCE_NAME`, `SOURCE_HASH`, `SEQUENCE_BASE`,
`TDC_FILE_HEADER`, `TDC_BLOCK_TABLE`.

### Interface Description Block (one per session and channel)

For each TDC capture-table entry *k* the writer emits one IDB for the USB data channel and, when
the source has them, further IDBs for the CC/PD channel, the analog channel and digital I/O.
Interface ids therefore identify (session, channel), and `frame.interface_id` in Wireshark
separates sessions.

| Field / option | Value |
|---|---|
| `LinkType` | `LINKTYPE_USB_TAP` (placeholder 147) |
| `SnapLen` | 0 (no limit) or the analyzer's truncation length when known |
| `if_name` | `<analyzer>/<session>[/<channel>]`, e.g. `beagle480/2`, `beagle480/2/cc` |
| `if_description` | free text: model, Data Center capture number, start time |
| `if_tsresol` | `9` (nanoseconds). Fixed; see [Timestamps](#timestamps-and-clock-domains) |
| `if_tsoffset` | not written (0). **Open** |
| `if_speed` | the nominal bit rate of the session's detected speed if constant, else omitted |
| `if_hardware` | analyzer model |
| custom 2989, PEN, subtype 1 (`usbtap_if_info`) | TLVs `SESSION` (required), `CHANNEL` (required), `TICK_RATE` (required), `SESSION_START`, `SESSION_STOP`, `SESSION_DURATION_TICKS`, `ANALYZER`, `ANALYZER_SERIAL`, `SOFTWARE`, `INTERFACE_IDS`, `TDC_CAPTURE_ENTRY_RAW` (on the USB channel IDB only) |

Why one IDB per session rather than one per file: the ISB then gives per-session start/stop and
record counts in standard options; `if_speed` and `SnapLen` can differ per session; and a
merge of two files is just more interfaces. Why not one IDB per speed (as today): speed is a
per-packet property in a capture that spans a re-enumeration, and splitting one bus across
interfaces hides that. **Open** whether sessions other than the one Data Center shows should
be exported by default.

### Enhanced Packet Block (one per analyzer record)

| Field / option | Value |
|---|---|
| `Interface ID` | the (session, channel) IDB |
| `Timestamp` | `SESSION_START_ns + floor(TS_TICKS · 10^9 · den / num)`, in ns since the Unix epoch |
| `Captured Packet Length` | `header_len` + payload bytes present |
| `Original Packet Length` | `header_len` + `PAYLOAD_INFO.original_len` when truncated and known; else equal to captured |
| `Packet Data` | pseudo-header, payload, zero padding to 4 |
| `epb_flags` | direction bits 0–1 from `DIRECTION` (1 upstream → `01` inbound, 1 downstream → `10` outbound); bit 24 when `CRC_ERROR`; bit 31 when `SYMBOL_ERROR`; bit 26 (too short) when `TRUNCATED` or fragment; others 0 |
| `epb_packetid` | `SEQUENCE`. Required |
| `epb_dropcount` | only on `OVERFLOW` events when the source gives a count |
| `opt_comment` | the user comment, duplicated from `COMMENT` so that Wireshark shows it without a dissector. Optional |

EPBs are written in the **source stream order**, not in timestamp order. The TDC writes children
before parents and is not sorted by time; keeping that order preserves `SEQUENCE` monotonicity
within the file, lets a dissector see a transaction's packets before the transaction, and makes
`TDC_RAW` reconstruction a single pass. pcapng does not require monotonic timestamps; Wireshark
sorts on demand. **Open** whether to offer a time-sorted export mode.

### Interface Statistics Block (one per IDB, at the end)

`isb_starttime` / `isb_endtime` from the session start/stop, `isb_ifrecv` = number of EPBs
written on the interface, `isb_ifdrop` = 0 unless the source reports overflow.

### Custom block data layout

All custom blocks defined here are type `0x00000BAD` (safe to copy) and have no pcapng options;
the custom data runs to `Block Total Length − 4`. The copyable type is right because the data is
self-contained and remains valid after a file is filtered or merged (interface ids are rewritten
by `mergecap` only in ways it applies to all blocks it understands; see the compatibility
section).

```
offset  size  field
0       u32   Block Type = 0x00000BAD
4       u32   Block Total Length
8       u32   Private Enterprise Number       (section byte order)
12      u32   subtype                          (little-endian, table below)
16      u8    version = 1
17      u8    flags = 0
18      u16   reserved = 0
20      ...   TLVs
end-4   u32   Block Total Length
```

| Subtype | Name | TLVs | Multiplicity |
|---|---|---|---|
| 1 | reserved (used as the custom *option* subtype for SHB/IDB info) | | |
| 2 | `SOURCE_FILE` | `SOURCE_*`, `SEQUENCE_BASE`, `TDC_FILE_HEADER`, `TDC_BLOCK_TABLE` | once per source |
| 3 | `DEVICE_TABLE` | `DEVICE_ENTRY` × n, `TDC_FOOTER_RAW`, `TDC_STREAM_TAIL` | once per source |
| 4 | `CLOCK_MAP` | `CLOCK_DOMAIN`, `CLOCK_ANCHOR`, `CLOCK_MODEL` | any |
| 5 | `CORRELATION` | `CORR_MATCH` × n | any; writers SHOULD batch a few thousand matches per block |
| 6 | `ADDRESS_MAP` | `ADDRESS_BINDING` × n | any |
| 7 | `FILE_REFS` | `FILE_REF` × n | any |

Custom *options* (2989) use the same `PEN, u32 subtype` prefix followed directly by TLVs (no
version byte; the option's subtype is the version anchor): subtype 1 = `usbtap_file` on the SHB
and `usbtap_if_info` on an IDB; subtype 0x10 = embedded pseudo-header (Profile B only).

### Placeholders

| Placeholder | Value used in this document and in examples | What is needed |
|---|---|---|
| Private Enterprise Number | **32473**, the number RFC 5612 reserves for documentation. It MUST NOT appear in a released file | Apply at <https://www.iana.org/assignments/enterprise-numbers/> (free, a few weeks). Replace in `src/` and here |
| Link type | **147** (`LINKTYPE_USER0`), with the IDB custom option as the real marker | Request `LINKTYPE_USB_TAP` on tcpdump-workers with this document |
| Format name | `usbtap` | |

## Timestamps and clock domains

The Beagle USB 480 and the USB 2 side of the USB 5000 run a 60 MHz sample clock (Confirmed
(beagle.so); 48 MHz on the Beagle USB 12). One tick is 50/3 ns, which has no finite decimal or
binary expansion, so no `if_tsresol` value (10^-n or 2^-n) can express ticks exactly:

* `if_tsresol = 9` (ns) loses up to 2/3 ns per timestamp and, worse, makes `ticks` unrecoverable
  (three ticks map to 50 ns; 1 tick → 16 ns, 2 → 33 ns).
* `if_tsresol = 12` (ps) is exact for one tick (16,666.67 ps is not an integer either) — no.
* `if_tsresol = 0x80 | n` can represent 2^-n only.

The format therefore keeps two timestamps per record:

1. **`TS_TICKS`** (u64) in the pseudo-header, the analyzer's own count since the session epoch,
   with the rate declared once per interface in `TICK_RATE` as a rational. This is the value of
   record. It round-trips the TDC `timestamp` field bit for bit and supports any future rate
   (500 MHz on the USB 5000's USB 3 side, picosecond timestamps on a USB4 analyzer) without a
   format change.
2. The **EPB timestamp** in ns, derived by `floor(ticks · 10^9 · den / num)` added to the session
   start, for every tool that does not know the pseudo-header. Writers MUST use floor so that two
   records with different ticks never swap order after rounding (floor is monotonic).

`DURATION_TICKS` is kept in ticks for the same reason. Session start and stop in the TDC are Unix
seconds, so `SESSION_START` is an exact multiple of 10^9 and the EPB timestamps are exact to the
ns truncation only.

Why not `if_tsoffset = SESSION_START` with a relative EPB timestamp: that would make the EPB value
equal to `ticks·1000/60` and visibly tie it to the session, but tools that ignore `if_tsoffset`
would show 1970 and mis-merge. Readers MUST honour `if_tsoffset` if a writer other than this repo
sets it, per the pcapng draft. **Open.**

Two interfaces of the same session (USB and CC) share the tick domain by construction: the
analyzer stamps both from the same counter, and the `INTERFACE_IDS` TLV says so. Interfaces of
*different* sessions or sources are different clock domains, related only through `CLOCK_MAP`
blocks ([Correlation](#correlation-with-os-level-captures)).

## Capture sessions, capture table and device table

* **Sessions.** TDC capture-table entry → IDB set as above. The entry's confirmed fields
  (`id`, `start`, `stop`, `duration_ticks`, `tick_rate`) become `SESSION`, `SESSION_START`,
  `SESSION_STOP`, `SESSION_DURATION_TICKS`, `TICK_RATE`; the unknown `u32 = 3` at offset 5 and
  the version-dependent trailer are inside `TDC_CAPTURE_ENTRY_RAW`, and the reconstruction uses
  only the raw TLV.
* **Records of a session** go on that session's interface(s). The record's `capture` byte is
  reproduced from `SESSION`.
* **Device table.** The TDC footer is one `DEVICE_TABLE` block per source with `TDC_FOOTER_RAW`.
  The `DEVICE_ENTRY` TLVs are optional until the footer is decoded (**Unknown**, see the mapping
  table); the slots for descriptors and per-endpoint counters are reserved so that filling them
  in later does not change the format. `DEVICE_REF` on records points at `DEVICE_INDEX`, which
  for TDC equals the status element's device index.
* **Comments** (element 0x15) are kept verbatim in the `TDC_ELEMENT` and duplicated as UTF-8 in
  `COMMENT` and `opt_comment`.

## Events, transactions and groups

* A TDC record with element 0x0F is an `EVENT` EPB: `EVENT` from the code table above, `SPEED`
  when the event names one, `ANALYZER_STATUS_RAW` from the element's status word, no payload.
* A record with element 0x0C is a `GROUP` EPB with `GROUP_INFO.kind = 1`, `subkind` = the token
  PID implied by the 0x0C kind byte (0x0C → SETUP 0x2D, 0x03 → IN 0x69, 0x07 → OUT 0xE1; other
  kinds → 0, Structural), `count` = number of children, `CHILDREN` = the child sequence numbers
  in stored order, `ADDRESS` from element 0x03.
* Elements 0x05 (+0x14), 0x06 (+0x16), 0x0A/0x07 map to `GROUP_INFO` kinds 2, 3 or 4 (0x06 flags
  0x11 = keep-alive run), 5, with `first`/`last` frame numbers from 0x06.
* A record whose only content element is 0x01 is `CAPTURE_CONTROL` with `EVENT = CAPTURE_START`.
* A record with only a comment is `MARKER`.

Zero-length-payload EPBs rather than custom blocks, because events and groups have a time and an
interface, must sort with packets, and must be filterable in the packet list.

## Power Delivery / Type-C side channel

A PD-capable analyzer (or a Twinkie-class sniffer whose dump is converted) gets a second IDB per
session with `CHANNEL = 2`, the same `TICK_RATE` and `SESSION_START`, and `INTERFACE_IDS`
pointing at the data-line IDB. Records on it:

| What | `record_kind` | Required TLVs | Payload |
|---|---|---|---|
| PD message (any SOP*) | `PD_MESSAGE` | `TS_TICKS`, `DURATION_TICKS`, `SPEED = PD_BMC`, `PD_FRAME`, `PAYLOAD_INFO{format 8, encoding 3}` | header, data objects, extended header if any, CRC32, as decoded from 4b5b |
| GoodCRC | `PD_MESSAGE` with `PD_FRAME.flags` bit 2 | as above | the GoodCRC header and CRC |
| Hard Reset / Cable Reset | `PD_MESSAGE`, `PD_FRAME.sop` 6/7 | `TS_TICKS`, `DURATION_TICKS`, `PD_FRAME` | none (ordered set only) |
| Undecodable frame | `PD_MESSAGE`, `sop` 8 | `PD_FRAME`, `PD_RAW_BMC` or `PD_RAW_SYMBOLS` | format 9 symbols if available |
| CC attach / detach / orientation / Rp level change | `CC_EVENT` | `EVENT` (0x0300 series), `CC_STATE` | none |
| VBUS / VCONN / CC sample | `ANALOG_SAMPLE` | `POWER_SAMPLE` or `POWER_SAMPLE_RUN` | none |

Both raw and decoded forms are allowed in one record: payload = decoded bytes, `PD_RAW_BMC` /
`PD_RAW_SYMBOLS` = what was on the line. A dissector verifies the CRC32 from the bytes; the
analyzer's own verdict is `PD_FRAME.flags` bit 0 so the two can disagree visibly.

Because the CC interface shares the data-line tick domain, "which USB transaction was in flight
when the Request was sent" is a plain comparison of `TS_TICKS`, and correlation to OS-level
captures goes through the same `CLOCK_MAP` as the data lines. If a dedicated
`LINKTYPE_USB_PD` is ever registered, its packet bytes are intended to be exactly payload format
8; the TAP header would stay for the metadata.

## Correlation with OS-level captures

The same transfer can be seen by an OS capture (USBPcap IRPs, usbmon URBs, macOS IOUSBHost
requests) and, on the wire, as transactions and packets. Linking them answers "which packets
did this URB produce" and "what did the host think this retry was". Three problems:
identity, clocks and addresses.

### Carrying both captures

**Preferred: one file.** The OS capture's IDBs (`LINKTYPE_USBPCAP`, 220, 266, 186) and EPBs are
copied unchanged into the same section as the TAP interfaces, which pcapng allows (one link type
per IDB, any mix per section). Standard dissectors keep working on them. The writer MUST NOT
alter the OS EPB bodies; it MAY add `epb_packetid` to them if they had none, choosing values
disjoint from the TAP sequence range, and MUST record that in a `SOURCE_FILE` block for the OS
source (`SOURCE_FORMAT` = 2 pcapng-OS, with its `SEQUENCE_BASE`).

**Alternative: separate files.** Each file carries a `FILE_ID`; the correlation blocks live in
either file (or a third, which contains only SHB, `FILE_REFS` and correlation blocks) and
`PACKET_REF.interface_id` then refers to interfaces *of the file named by the preceding
`FILE_REF`* with the same `role`. One file is simpler for every tool; separate files avoid
rewriting a large OS capture. Both are valid; one file is RECOMMENDED.

### Identity: `PACKET_REF`

A reference names an EPB by, in order of preference, `epb_packetid` (stable across filtering),
its native header id (`irpId`, URB id + event type, Darwin unique id + request type; stable
across any rewrite because it is inside the packet), or its ordinal among its interface's EPBs
(fragile; only for files without ids). A `CORR_MATCH` holds one or more OS refs and one or more
PHY refs. Typical shapes:

* USBPcap bulk IN IRP (one `irpId`, submit + complete) ↔ *n* PHY `GROUP` transactions (IN/DATA/ACK
  each) plus the NAK groups between them. One match, relation 1, PHY refs are the transaction
  sequence numbers (their packets follow via `CHILDREN`).
* usbmon control URB (`'S'` and `'C'` events) ↔ PHY SETUP, DATA and STATUS transactions.
  Relation 3.
* An OS URB whose PHY side was lost (analyzer not yet connected) → match with relation 4 and no
  PHY refs, so the absence is recorded rather than silent.

### Clocks

Host timestamps (µs or ns, host clock) and analyzer ticks (free-running oscillator, starting at
0 at the session start, with only a 1-second-resolution wall-clock anchor in the capture table)
drift apart by tens of ppm and are offset by an unknown fraction of a second plus host-side
latency between the wire and the URB completion timestamp. `CLOCK_MAP` records what the
correlating tool concluded: `CLOCK_ANCHOR`s are the raw simultaneities it used (e.g. the SETUP
packet of the first GET_DESCRIPTOR vs the submit timestamp of the matching IRP, with an
uncertainty of the host's scheduling jitter), and `CLOCK_MODEL` is the fitted offset and drift,
with validity range and method, so that a later tool can re-derive the alignment or refit with
more anchors without re-running the matcher. Readers displaying both sides on one time axis
MUST apply the model and SHOULD show the uncertainty.

### Addresses

The analyzer sees USB addresses 0–127 that are reassigned after every bus reset; the OS sees
(bus, device address), USBPcap a 16-bit `device`, Darwin a `locationID` encoding the port path.
`ADDRESS_BINDING` states, per interval of PHY ticks, which OS identity a PHY address belongs to
and which `DEVICE_TABLE` entry it is. The writer emits a new binding at every SET_ADDRESS it
observes on the wire (the natural boundary) and, when it cannot match, a binding with method 0
and confidence 0 so the gap is explicit.

### Inline shortcut

For the common one-URB-to-one-transaction case a writer MAY put `CORR_OS_REF` directly in the
PHY record's pseudo-header. It is a convenience for dissectors; the `CORRELATION` block is the
normative form and a writer that uses the inline form MUST also emit the block (duplication is
cheap; the block is indexed, the inline form is not).

## TDC to pcapng mapping table

Status is carried over from [`tdc-format.md`](tdc-format.md). "Carried" means the bytes are
present in a passthrough TLV regardless of status; "Decoded" names the generic TLV that also
expresses the field. **Open** rows are the known gaps that the `beagle.so` work is expected to
fill; filling them changes a reader's interpretation, never the layout.

| TDC field | Status | pcapng location | Decoded as |
|---|---|---|---|
| File header: magic, signature, `header_len`, writer version, `saved_at`, `format_version`, unknown bytes, element type table | Confirmed / Structural / Unknown | `SOURCE_FILE` → `TDC_FILE_HEADER` (verbatim) | `SOURCE_FORMAT.version` = `format_version` |
| Block header: type, compressed length | Structural / Confirmed | `SOURCE_FILE` → `TDC_BLOCK_TABLE` | |
| Block header u32 at offset 4 | **Unknown / Open** | `TDC_BLOCK_TABLE.unknown_at_4` | none; needed only to rebuild the compressed file |
| FastLZ level per block | Confirmed | `TDC_BLOCK_TABLE.level` | |
| Capture entry: id | Confirmed | IDB `usbtap_if_info` → `SESSION`; every EPB `SESSION` | |
| Capture entry: u32 = 3 at offset 5 | Unknown | `TDC_CAPTURE_ENTRY_RAW` | `ANALYZER.model` is *not* derived from it |
| Capture entry: start / stop | Confirmed / Structural | `SESSION_START` / `SESSION_STOP`, ISB `isb_starttime`/`isb_endtime`; raw in `TDC_CAPTURE_ENTRY_RAW` | |
| Capture entry: duration ticks, tick rate | Confirmed | `SESSION_DURATION_TICKS`, `TICK_RATE`; raw | |
| Capture entry trailer (14/15/16 bytes) | Unknown | `TDC_CAPTURE_ENTRY_RAW` | |
| Record: flags, byte 3, reserved 20, capture flags | Structural / Unknown | `TDC_RECORD_HEADER` | |
| Record: length | Structural | rebuilt from TLVs | |
| Record: sequence | Confirmed | `SEQUENCE` (+ `SEQUENCE_BASE`), `epb_packetid` | |
| Record: nested | Structural | `TDC_RECORD_HEADER.nested` | |
| Record: capture | Confirmed | `SESSION` | interface choice |
| Record: timestamp (ticks) | Confirmed | `TS_TICKS`; EPB timestamp derived | |
| Record: duration (ticks) | Confirmed | `DURATION_TICKS` | |
| Element 0x00 byte 0 bits 0–2 (speed 1/3/4) | Confirmed (beagle.so) | `TDC_ELEMENT` 0x00 | `SPEED` |
| Element 0x00 byte 0 bit 0x20 (error) | Confirmed | `TDC_ELEMENT` 0x00 | `ERROR_FLAGS` bit 31 |
| Element 0x00 byte 0 bits 0x10, 0x40 | **Unknown / Open** (co-occurrence only: 0x10 unmatched records, 0x40 SOF records) | `TDC_ELEMENT` 0x00 | none yet |
| Element 0x00 byte 1 | Unknown | `TDC_ELEMENT` 0x00 | none |
| Element 0x00 bytes 2–3 device index | Structural | `TDC_ELEMENT` 0x00 | `DEVICE_REF` (absent for 0xFFFF) |
| Element 0x01 capture started | Confirmed | `TDC_ELEMENT` 0x01 | `record_kind` `CAPTURE_CONTROL`, `EVENT = CAPTURE_START` |
| Element 0x02 bus record | Structural | `TDC_ELEMENT` 0x02 | none (kind comes from 0x0F/0x06) |
| Element 0x03 pid, kind, address, endpoint | Confirmed (pid/addr/ep); kind Structural | `TDC_ELEMENT` 0x03 | `ADDRESS`; `GROUP_INFO.subkind` for transactions |
| Element 0x04 group info | addr/ep Confirmed; 2 bytes Unknown | `TDC_ELEMENT` 0x04 | `ADDRESS` |
| Element 0x05 collapsed count | Confirmed | `TDC_ELEMENT` 0x05 | `GROUP_INFO` kind 2 |
| Element 0x06 SOF group (count, flags 0x10/0x11, first, last) | Confirmed; flags Structural | `TDC_ELEMENT` 0x06 | `GROUP_INFO` kind 3/4, `first`, `last` |
| Element 0x06 error flag on HS SOF groups | **Unknown / Open** | `TDC_ELEMENT` 0x00/0x06 | `ERROR_FLAGS` bit 31 only |
| Elements 0x07, 0x08, 0x09, 0x0A orphan groups | Unknown / count Confirmed | `TDC_ELEMENT` | `GROUP_INFO` kind 5 with `count` from 0x0A |
| Element 0x0B status word | Confirmed (beagle.so) | `TDC_PACKET_ELEMENT.status`, `ANALYZER_STATUS_RAW` | `ERROR_FLAGS` |
| Element 0x0B length, bytes | Confirmed | EPB payload (`PAYLOAD_INFO.format` 0) | `usbll` |
| Element 0x0C transaction kind, children | Children Confirmed; kinds inferred | `TDC_ELEMENT` 0x0C | `GROUP_INFO` kind 1, `CHILDREN` |
| Element 0x0F code | Confirmed for listed codes; others Unknown | `TDC_ELEMENT` 0x0F | `EVENT` (table above) |
| Element 0x0F status word | Confirmed (beagle.so) | `TDC_ELEMENT` 0x0F, `ANALYZER_STATUS_RAW` | `ERROR_FLAGS` |
| Element 0x11 child list with prefix | Structural | `TDC_ELEMENT` 0x11 | none |
| Elements 0x12, 0x13, 0x17 flags | Unknown | `TDC_ELEMENT` | none |
| Elements 0x14, 0x16 child lists | Structural | `TDC_ELEMENT` | `CHILDREN` |
| Element 0x15 comment (UTF-16LE) | Confirmed | `TDC_ELEMENT` 0x15 | `COMMENT`, `opt_comment` |
| Any other element tag | Unknown | `TDC_ELEMENT` | none |
| Footer version, device table, statistics | Unknown | `DEVICE_TABLE` → `TDC_FOOTER_RAW` | `DEVICE_ENTRY` once decoded (**Open**) |
| USB 3 element tags (Beagle 5000) | **Unknown / Open** | `TDC_ELEMENT` (works today, undecoded) | USB 3 TLVs once seen |

## Lossless round trip

A TDC → pcapng → TDC round trip is defined at the level of the **decompressed stream** (capture
table, records, footer) and the **file header**: those bytes MUST be reproduced exactly. The
compressed file is reproducible only if the FastLZ encoder matches Data Center's and the block
field at offset 4 is written back from `TDC_BLOCK_TABLE`; since that field's meaning is open,
a rebuilt file is byte-identical to the original only when the same blocks are re-emitted
with the same compressor, which this repo does not promise. `SOURCE_HASH` lets a reader tell
the two cases apart.

Reconstruction, per section:

1. File header ← `TDC_FILE_HEADER`.
2. Capture table ← `TDC_CAPTURE_ENTRY_RAW` of each USB-channel IDB, ordered by `SESSION`.
3. Records ← EPBs on TAP interfaces that carry `TDC_RECORD_HEADER` or `TDC_RAW_RECORD`, in
   file order (which is stream order). For each:
   * `TDC_RAW_RECORD` present → copy it.
   * Otherwise write `flags`, `length` (computed), `byte3`, `sequence = SEQUENCE − SEQUENCE_BASE`,
     `nested` as u32, `reserved20`, `capture = SESSION`, `capture_flags`, `timestamp = TS_TICKS`,
     `duration = DURATION_TICKS`, then the elements: walk the TDC TLVs in order; `TDC_ELEMENT` →
     `tag, kind, 6 + len(payload), payload`; `TDC_PACKET_ELEMENT` → `tag, kind, 14 + n, status,
     n, payload` where `payload` is the EPB data after `header_len` (n = captured − header_len).
4. Footer ← `0x06, version, length, data` from `TDC_FOOTER_RAW`, then `TDC_STREAM_TAIL`.

Generic TLVs, `epb_*` options, ISBs, correlation blocks and `opt_comment` are ignored by this
procedure, which is what makes them free to improve: a later writer that decodes more (say, the
footer into `DEVICE_ENTRY`s) still emits the same `TDC_*` TLVs, and an older reader rebuilds the
same file. `tests/` SHOULD contain this round trip over every sample in USBTraces.

Writers MUST emit exactly one `TDC_*` TLV per element and MUST NOT reorder them. They MUST NOT
"normalise" element payloads (for example rewriting a comment's UTF-16 or dropping a zero-length
0x11 list).

## Profiles

* **Profile A (canonical)**: everything above. File extension `.pcapng`.
* **Profile B (usbll compatibility)**: for USB 2 `PACKET` records only, the writer MAY instead
  emit the EPB on an IDB of `LINKTYPE_USB_2_0_LOW_SPEED` / `_FULL_SPEED` / `_HIGH_SPEED`
  (one per session and speed; `LINKTYPE_USB_2_0` when the speed is unknown) with the raw packet
  bytes as body and the entire pseudo-header, byte for byte, in a custom EPB option 2989
  `PEN, subtype 0x10, pseudo-header`. Events, groups, PD and everything else still go on TAP
  interfaces, so a Profile B file contains both kinds of IDB. Readers MUST accept both profiles;
  the reconstruction above treats the option content exactly like a pseudo-header. Profile B
  exists so that a stock Wireshark dissects the packets today; it is not recommended once the
  TAP dissector is available, because `editcap`/`mergecap` may drop the option and legacy
  `.pcap` output loses it entirely.

## Worked examples

Generated by `scratchpad/gen_examples.py` (kept out of the repo); all values little-endian.
The PEN is the documentation placeholder `32473` = `d9 7e 00 00`.

### Interface description block for capture session 2

Link type 147 (placeholder), snaplen 0x40000, `if_name` `beagle480/2`, `if_description`,
`if_tsresol` 9, then the `usbtap_if_info` option (2989) with `SESSION` 2, `CHANNEL` 1,
`TICK_RATE` 60,000,000/1, `SESSION_START` 1,414,535,317 s, `SESSION_STOP` +83 s,
`SESSION_DURATION_TICKS` 4,980,000,000 and the 45-byte raw capture entry.

```
0000  01 00 00 00 f0 00 00 00 93 00 00 00 00 00 04 00   IDB, len 240, linktype 147, snaplen
0010  02 00 0b 00 62 65 61 67 6c 65 34 38 30 2f 32 00   if_name "beagle480/2"
0020  03 00 31 00 54 6f 74 61 6c 20 50 68 61 73 65 20   if_description ...
0030  42 65 61 67 6c 65 20 55 53 42 20 34 38 30 2c 20
0040  44 61 74 61 20 43 65 6e 74 65 72 20 63 61 70 74
0050  75 72 65 20 32 00 00 00 09 00 01 00 09 00 00 00   if_tsresol = 9
0060  ad 0b 84 00 d9 7e 00 00 01 00 00 00 0d 00 04 00   opt 2989 len 132: PEN, subtype 1, SESSION
0070  02 00 00 00 24 00 01 00 01 00 00 00 23 00 10 00   =2; CHANNEL=1; TICK_RATE
0080  00 87 93 03 00 00 00 00 01 00 00 00 00 00 00 00   60000000 / 1
0090  20 00 08 00 00 92 07 54 60 70 a1 13 21 00 08 00   SESSION_START (ns); SESSION_STOP
00a0  00 10 37 a7 73 70 a1 13 22 00 08 00 00 c5 d4 28   SESSION_DURATION_TICKS
00b0  01 00 00 00 20 70 2d 00 05 02 00 00 00 03 00 00   TDC_CAPTURE_ENTRY_RAW, 45 bytes:
00c0  00 95 18 50 54 e8 18 50 54 00 c5 d4 28 01 00 00   kind 05, id 2, 3, start, stop,
00d0  00 00 87 93 03 00 08 00 00 00 00 00 00 00 01 00   duration, 60 MHz, trailer
00e0  00 00 00 00 00 00 00 00 00 00 00 00 f0 00 00 00   pad, opt_endofopt, len 240
```

### Enhanced packet block for an ACK packet

Source record (sequence 18 of `serial/ftdi/FT230X_Basic_UART_w7_init.tdc`, the one in
`src/tdc/record.rs`'s test), 65 bytes:

```
00 41 00 00  12 00 00 00  01 00 00 00  14 00 00 00  02 00  00 d2 30 19 00 00 00 00  2d 00 00 00
00 03 0a 00 00 00  03 00 00 00          status: full speed, device 0
03 03 0a 00 00 00  02 ff 00 00          packet info: PID nibble 2 (ACK), single, addr 0, EP 0 OUT
0b 03 0f 00 00 00  00 00 00 00  01 00 00 00  d2    packet: status 0, 1 byte, 0xD2
```

Ticks 0x1930D200 = 422,629,888 → 7.043831466… s after the session start, so the EPB timestamp
is 1,414,535,324,043,831,466 ns = `0x13A17061_F7DFE8AA` (floor). The pseudo-header is 132 bytes
and the payload 1 byte; captured = original = 133, padded to 136; `epb_packetid` = 18.

```
0000  06 00 00 00 b8 00 00 00 00 00 00 00 61 70 a1 13   EPB len 184, iface 0, ts high
0010  aa e8 df f7 85 00 00 00 85 00 00 00 01 01 84 00   ts low, caplen 133, origlen 133 | v1, PACKET, hdr 132
0020  01 00 08 00 00 d2 30 19 00 00 00 00 02 00 08 00   TS_TICKS 0x1930d200; DURATION_TICKS
0030  2d 00 00 00 00 00 00 00 03 00 04 00 02 00 00 00   45; SPEED FULL
0040  08 00 08 00 12 00 00 00 00 00 00 00 0d 00 04 00   SEQUENCE 18; SESSION
0050  02 00 00 00 07 00 04 00 00 00 ff ff 0c 00 04 00   2; ADDRESS 0/0 OUT, no hub; DEVICE_REF
0060  00 00 00 00 10 00 08 00 00 00 00 00 00 00 00 00   0; PAYLOAD_INFO fmt 0 enc 0, not truncated
0070  00 70 08 00 00 00 01 00 14 00 00 00 01 70 08 00   TDC_RECORD_HEADER flags 0, byte3 0, nested 1, cflags 0, 20
0080  00 03 00 00 03 00 00 00 01 70 08 00 03 03 00 00   TDC_ELEMENT 00: 03 00 00 00; TDC_ELEMENT 03:
0090  02 ff 00 00 02 70 08 00 0b 03 00 00 00 00 00 00   02 ff 00 00; TDC_PACKET_ELEMENT 0b, status 0
00a0  d2 00 00 00 05 00 08 00 12 00 00 00 00 00 00 00   payload D2 + pad; epb_packetid 18
00b0  00 00 00 00 b8 00 00 00                           opt_endofopt; len 184
```

Reconstruction: `length = 30 + (6+4) + (6+4) + (6+8+1) = 65`; `sequence = 18 − 0`;
`capture = 2`; the three elements come out in TLV order; the packet element gets
`status 0, n = 133 − 132 = 1, D2`.

### Enhanced packet block for a bus event

A synthetic full-speed-detected record (no event record has been published byte for byte), 57
bytes: flags 0x10, sequence 3, not nested, capture 2, tick 8000, duration 0, elements
`00 (03 00 00 00)`, `02 ()`, `0f (0b, status 0)`. EPB timestamp = start + 133,333 ns (floor of
133,333.33).

```
0000  06 00 00 00 a0 00 00 00 00 00 00 00 60 70 a1 13   EPB len 160
0010  d5 9a 09 54 70 00 00 00 70 00 00 00 01 02 70 00   caplen = origlen = 112 | v1, EVENT, hdr 112
0020  01 00 08 00 40 1f 00 00 00 00 00 00 02 00 08 00   TS_TICKS 8000; DURATION_TICKS
0030  00 00 00 00 00 00 00 00 03 00 04 00 02 00 00 00   0; SPEED FULL
0040  06 00 04 00 06 00 00 00 08 00 08 00 03 00 00 00   EVENT SPEED_DETECTED; SEQUENCE
0050  00 00 00 00 0d 00 04 00 02 00 00 00 00 70 08 00   3; SESSION 2; TDC_RECORD_HEADER
0060  10 00 00 00 14 00 00 00 01 70 08 00 00 03 00 00   flags 0x10, nested 0, 20; TDC_ELEMENT 00
0070  03 00 00 00 01 70 04 00 02 03 00 00 01 70 09 00   TDC_ELEMENT 02 (empty); TDC_ELEMENT 0f, 5 bytes:
0080  0f 03 00 00 0b 00 00 00 00 00 00 00 05 00 08 00   code 0b, status 0, pad; epb_packetid
0090  03 00 00 00 00 00 00 00 00 00 00 00 a0 00 00 00   3; opt_endofopt; len 160
```

No payload, so caplen equals `header_len`.

### Enhanced packet block for a PD Source_Capabilities message (synthetic)

On interface 1 (the CC channel of session 2): SOP, CC1, CRC good and GoodCRC seen 30 µs
(1800 ticks) later, PD 3.0 header `0x11A1` (Source_Capabilities, one PDO, DFP, Source),
one PDO, CRC32; payload format 8, encoding BMC.

```
0000  06 00 00 00 8c 00 00 00 01 00 00 00 60 70 a1 13   EPB len 140, iface 1
0010  5e 41 ac ce 5a 00 00 00 5a 00 00 00 01 04 50 00   caplen 90 | v1, PD_MESSAGE, hdr 80
0020  01 00 08 00 15 cd 5b 07 00 00 00 00 02 00 08 00   TS_TICKS 123456789; DURATION_TICKS
0030  80 25 00 00 00 00 00 00 03 00 04 00 40 00 00 00   9600; SPEED PD_BMC
0040  08 00 08 00 07 00 00 00 00 00 00 00 0d 00 04 00   SEQUENCE 7; SESSION
0050  02 00 00 00 00 40 08 00 01 01 03 02 08 07 00 00   2; PD_FRAME: SOP, CC1, flags 03, rev 2, 1800
0060  10 00 08 00 08 03 00 00 00 00 00 00 a1 11 2c 91   PAYLOAD_INFO fmt 8 enc 3; payload: header 11A1,
0070  01 08 12 34 56 78 00 00 05 00 08 00 07 00 00 00   PDO 0801912C, CRC 78563412; epb_packetid 7
0080  00 00 00 00 00 00 00 00 8c 00 00 00
```

### Correlation block: one USBPcap IRP realised by three PHY transactions

Interface 3 is a `LINKTYPE_USBPCAP` IDB copied into the section. Method 4 (heuristic:
timing + address + length), confidence 230/255, relation 1.

```
0000  ad 0b 00 00 90 00 00 00 d9 7e 00 00 05 00 00 00   CB len 144, PEN, subtype 5 CORRELATION
0010  01 00 00 00 20 50 74 00 04 e6 01 00 21 50 18 00   v1; CORR_MATCH len 116: method 4, conf 230, rel 1
0020  03 01 00 00 03 00 00 00 c0 e5 b3 2a 01 d0 ff ff   PACKET_REF native, role OS, iface 3, irpId
0030  00 00 00 00 00 00 00 00 21 50 18 00 01 02 00 00   id2 0; PACKET_REF epb_packetid, role PHY,
0040  00 00 00 00 14 00 00 00 00 00 00 00 00 00 00 00   iface 0, id 20
0050  00 00 00 00 21 50 18 00 01 02 00 00 00 00 00 00   PACKET_REF iface 0 id 19
0060  13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
0070  21 50 18 00 01 02 00 00 00 00 00 00 12 00 00 00   PACKET_REF iface 0 id 18
0080  00 00 00 00 00 00 00 00 00 00 00 00 90 00 00 00   len 144
```

### Clock map block

One anchor (PHY tick 0 on interface 0 ≙ 1,414,535,317.002118000 s on interface 3, ±1.5 ms,
method 3 regression, confidence 200) and the fitted model (offset +2.118 ms, drift +2,350 ppb,
valid for the whole 83 s session, uncertainty 1.5 ms).

```
0000  ad 0b 00 00 78 00 00 00 d9 7e 00 00 04 00 00 00   CB len 120, PEN, subtype 4 CLOCK_MAP
0010  01 00 00 00 11 50 20 00 00 00 00 00 03 00 00 00   v1; CLOCK_ANCHOR len 32: if_phy 0, if_other 3
0020  00 00 00 00 00 00 00 00 70 e3 27 54 60 70 a1 13   phy_ticks 0; other_time_ns
0030  60 e3 16 00 03 c8 00 00 12 50 38 00 00 00 00 00   unc 1500000 ns, method 3, conf 200 | CLOCK_MODEL len 56
0040  03 00 00 00 00 00 00 00 00 00 00 00 80 1d 3e 7e   if 0, if 3, ref_ticks 0, offset_ps 2118000000
0050  00 00 00 00 2e 09 00 00 00 00 00 00 00 00 00 00   drift_ppb 2350; valid_from 0
0060  00 00 00 00 00 c5 d4 28 01 00 00 00 00 2f 68 59   valid_to 4980000000; unc 1500000000 ps
0070  03 c8 00 00 78 00 00 00                           method 3, conf 200; len 120
```

## Compatibility and Wireshark

* **Stock Wireshark / tshark** opens a Profile A file, shows one frame per EPB with the correct
  time, interface, `epb_packetid` and comment, and labels the data "DLT 147" until a dissector
  is mapped via *DLT_USER*. OS-level interfaces in the same file dissect normally. Custom blocks
  and options are preserved on save (Wireshark copies `0x00000BAD` blocks and 2988/2989 options
  it does not understand; it drops 19372/19373 by design, which is why this format uses
  2989).
* **`usbtap` dissector** (to be written, Lua first, then C): registers for `LINKTYPE_USB_TAP`
  (and DLT_USER by preference), parses the pseudo-header into `usbtap.*` fields (`speed`,
  `ticks`, `duration`, `event`, `errors`, `seq`, `session`, `tdc.status`, ...), then for
  `PAYLOAD_INFO.format` 0 calls `usbll` with the speed (Wireshark's `usbll` takes the speed
  from the link type; the dissector selects the matching per-speed `usbll` entry point or sets
  its speed preference per packet), for format 8 a `usbpd` dissector that does not yet exist
  in Wireshark (libsigrokdecode's decoder is the reference), and for other formats shows the
  bytes. It builds the transaction tree from `GROUP` records and `CHILDREN`, and, when
  `CORRELATION` blocks are present (read through wiretap's custom-block hooks, as Wireshark's
  own Process Information blocks are), adds "realised by / realises" links.
* **`mergecap`** renumbers interfaces when merging sections; `PACKET_REF.interface_id`,
  `INTERFACE_IDS` and `ADDRESS_BINDING` would then be stale. Until a tool that understands the
  blocks rewrites them, a merged file is still parseable but its correlation is suspect; readers
  SHOULD check that every referenced interface carries `usbtap_if_info` with the expected
  `SESSION` and `CHANNEL` and flag mismatches. Keeping `SESSION` on every EPB is the mitigation.
* **Legacy `.pcap`**: Profile A survives conversion (link type and body only), losing session
  options, custom blocks and `epb_packetid`; the body still carries `SEQUENCE`, `SESSION`,
  `TS_TICKS`, so a reader can recover everything but the file-level tables and the tick rate
  (assume 60 MHz for Beagle; **Open** whether to repeat `TICK_RATE` in every header for this
  case, at 24 bytes per record).
* **`pcap-file` (Rust crate used by this repo)** supports custom options and arbitrary block
  types through its raw block API; the exporter will write option bytes itself.
* **Size**: a USB 2 packet costs about 130 bytes of pseudo-header plus 28 bytes of EPB framing,
  against roughly 65 bytes in the (FastLZ-compressed) TDC. Files are 3–5× larger before external
  compression and comparable after `zstd`. Writers MAY omit derived TLVs whose value is the
  default (`ERROR_FLAGS` = 0, `DIRECTION` unknown, `DEVICE_REF` absent).

## Open questions

1. **PEN and link type.** Apply for the PEN now (it gates any shared file); request
   `LINKTYPE_USB_TAP` once this document has had review. Until then 32473/147 are placeholders
   and files MUST be treated as experimental.
2. **Default profile.** Ship Profile A as default with `--profile usbll` for B, or default to B
   until the dissector is merged upstream?
3. **Sessions by default.** Export every capture session (this document) or only the one Data
   Center shows (current behaviour) unless `--all-captures`?
4. **`if_tsoffset`.** Leave 0 (chosen here) or set it to the session start for a cleaner
   relative timestamp at the cost of reader support?
5. **EPB order.** Source stream order (chosen) or timestamp order with a `--sort` option? Sorting
   breaks the single-pass reconstruction unless `SEQUENCE` is used to re-sort first.
6. **Device table decoding.** Waits on the footer being reversed; `DEVICE_ENTRY` is reserved.
   Should the writer attempt the partial decode (device/config/string descriptors are
   recognisable) now and mark it with a confidence flag, or wait?
7. **Beagle 5000 / USB 3.** The USB 3 TLVs are provisional; element tags, the USB 3 status bits
   and the 500 MHz tick domain need a real capture. Who can supply one?
8. **PD source.** No PD-capable capture exists in the repo. Is the first target a Twinkie
   `.sr` converter (sigrok → this format) or a Total Phase product with PD capture?
9. **Correlation: who assigns ids.** When merging an OS capture that has no `epb_packetid`, the
   writer adds it (chosen); alternatively rely on native ids only and never touch OS EPBs.
10. **`TICK_RATE` in every header** for legacy-pcap survival (24 bytes/record) or not?
11. **Block field at offset 4, HS SOF error flag, status bits 0x10/0x40**: carried opaquely;
    decode pending `beagle.so` / Data Center reversing. No format decision needed, but the
    mapping-table rows stay Open until then.
12. **Compression.** pcapng has no compression. Recommend `.pcapng.zst` and support reading it
    directly, or leave to the user?
13. **PD as its own link type.** If a `LINKTYPE_USB_PD` is registered upstream, emit CC records
    on it (losing the TAP metadata) or keep the TAP interface and add nothing? This document
    assumes the latter.

## References

* pcapng: <https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcapng> (draft-06, 2026-09)
* Link-type registry: <https://www.tcpdump.org/linktypes.html>;
  <https://www.tcpdump.org/linktypes/LINKTYPE_USB_2_0.html>;
  <https://www.tcpdump.org/linktypes/LINKTYPE_USB_LINUX_MMAPPED.html>;
  <https://www.tcpdump.org/linktypes/LINKTYPE_USB_DARWIN.html>;
  <https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcaplinktype-08>
* Per-speed USB 2.0 link types proposal: <https://seclists.org/tcpdump/2022/q2/1>
* Wireshark `usbll`: <https://wireshark.askapache.com/docs/dfref/u/usbll.html>;
  <https://lists.wireshark.org/archives/wireshark-commits/201907/msg00303.html>;
  <https://lists.wireshark.org/archives/wireshark-dev/201810/msg00016.html>
* Wireshark custom blocks and options: <https://wiki.wireshark.org/Development/PcapngCustom>
* USBPcap format: <https://desowin.org/usbpcap/captureformat.html>
* OpenVizsla frame format:
  <https://github.com/matwey/libopenvizsla/wiki/OpenVizsla-protocol-description>
* Twinkie USB-PD sniffer:
  <https://www.chromium.org/chromium-os/developer-library/guides/hardware-schematics/twinkie>
* RFC 5612, Enterprise Number for Documentation Use (32473)
* IANA Private Enterprise Numbers: <https://www.iana.org/assignments/enterprise-numbers/>
* Total Phase Beagle Protocol Analyzer User Manual (API section 6.8):
  <https://www.totalphase.com/support/articles/200472426-beagle-protocol-analyzer-user-manual/>
* [`tdc-format.md`](tdc-format.md) (PR #3 revision) and `src/tdc/`
