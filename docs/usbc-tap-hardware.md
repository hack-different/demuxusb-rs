# USB-C full-pin protocol analyzer: feasibility and design study

Status: design study, no hardware built. Written 2026-11-02 against `tdc-format.md` (PR #3)
and `pcapng-usb-spec.md` (PR #4). Figures marked *est.* are engineering estimates, not
measurements; part prices are single-quantity distributor or board-vendor list prices seen on
the day and will move.

## Summary

The question was whether a Beagle USB 5000 class analyzer can be built today, FPGA based, that
taps **every** pin of a USB-C connection, and whether it is worth building.

* **Feasible now, with commodity parts:** USB 2.0 (LS/FS/HS), USB 3.2 Gen 1 and Gen 2 (5 and
  10 Gb/s per lane, including Gen 2x2), USB PD on both CC lines, VCONN, VBUS voltage and current
  including EPR, both SBU lines (DisplayPort AUX, USB4 sideband, debug UART), and DisplayPort
  Alt Mode main link up to HBR3. One transceiver quad on a mid-range FPGA covers the four
  SuperSpeed pairs. A Beagle 5000 v2 lists at $6,000 with "limited availability"
  ([Total Phase](https://totalphase.com/products/beagle-usb5000-v2-usb2)); nothing open
  exists in this class, and the closest open tool, Cynthion ($210,
  [Adafruit](https://www.adafruit.com/product/6005)), stops at USB 2.0.
* **Feasible with effort, higher-end FPGA:** USB4 Gen 2 and Gen 3 (10 and 20 Gb/s per lane,
  2+2 lanes) and Thunderbolt 3 compatibility rates (10.3125 / 20.625 Gb/s). Needs 32 Gb/s class
  transceivers (Kintex UltraScale+ GTY or Agilex 5 group A), a low-loss PCB, and about 80 Gb/s
  of worst-case raw capture bandwidth. The protocol work (64b/66b, 128b/132b, RS-FEC, transport
  layer, sideband) is large but the specifications are public.
* **Not feasible in an FPGA:** USB4 Gen 4 (USB4 v2, 80/120 Gb/s). It is PAM-3 at 25.6 GBaud
  with 11b/7t coding and mandatory RS-FEC
  ([Synopsys](https://www.synopsys.com/articles/pam3-technology-implementation-usb4-v2.html));
  no FPGA transceiver family has a PAM-3 receiver. Out of scope.

**Recommendation: build it, in two steps.** First a *tap head*, a passive, orientation-agnostic
USB-C in-line board with every pin broken out to an FMC connector, used with an off-the-shelf
Kintex UltraScale+ KU5P board (about £1,000 for the whole board, see
[Parts](#parts)) that already has 16 GTY transceivers, PCIe Gen 3 x8 and DDR4. That gets a USB
2.0 + PD + analog + SBU analyzer with a few months of gateware, and USB 3.2 Gen 1/Gen 2 once
the SuperSpeed decode exists, all on the same hardware. Second, if USB4 capture is wanted, an
integrated board with the FPGA next to the connectors (the FMC connector is the limit at
20 Gb/s). The output of both is the pcapng USB TAP format from PR #4; the device clock is
designed to make that format's tick domain, PD side channel and OS correlation hooks direct
rather than emulated.

The one architectural decision that matters is **passive pick-off versus active in-line
regeneration** of the SuperSpeed pairs. This document chooses passive pick-off (fully
transparent, no gateware transmit path, cheapest) and keeps a footprint for an in-line retimer
as the fallback if signal integrity at Gen 2 or USB4 does not hold. The reasoning is in
[Tapping the SuperSpeed pairs](#tapping-the-superspeed-pairs).

## Reference class

| Product | Rates | Buffer | Timestamp | Probing | Host link | Price |
|---|---|---|---|---|---|---|
| Total Phase Beagle USB 5000 v2 Ultimate | USB 2.0, USB 3.0 Gen 1 (A/B connectors, no Type-C, no PD) | 4 GB + streaming | 2 ns (USB 3), 16.7 ns (USB 2) | in-line, "automatic receiver detection, SSC, polarity inversion" (architecture not published) | USB 3.0 | $6,000, limited availability |
| Teledyne LeCroy Mercury T2C | USB 3.2 Gen 2 Type-C, PD | 2 GB class | — | in-line Type-C | USB 3 | ~€2,400 class (reseller listing, unverified) |
| Teledyne LeCroy Voyager M4x | 1.2 Mb/s to USB4 Gen 3x2 40 Gb/s, TB3, PD, sideband, DP AUX | 16/32 GB | — | in-line "T.A.P.4", "compatible with active and passive cable environments" | USB 3 / GbE (600 Mb/s sustained) | quote only |
| Great Scott Gadgets Cynthion | USB 2.0 LS/FS/HS | host streaming | — | in-line (PHY) | USB 2 | $210 |
| Google Twinkie / Twonkie | PD on CC1/CC2, VBUS V/I (SPR only), VCONN V | host streaming (sigrok) | — | in-line interposer | USB FS | ~$50–100 |

Sources: [Beagle USB 5000 v2](https://totalphase.com/products/beagle-usb5000-v2-usb2),
[Voyager M4x](https://www.teledynelecroy.com/protocolanalyzer/usb/usb-voyager-m4x),
[Cynthion](https://www.adafruit.com/product/6005),
[Twinkie](https://www.chromium.org/chromium-os/developer-library/guides/hardware-schematics/twinkie).

Two observations shape the design. Both Total Phase ("receiver detection") and Teledyne
("passive cable environments") describe analyzers that stay transparent to the link's own
termination detection and training, which is the behaviour of a passive probe, not of a
retimer that terminates the link. And the vendors' host links (USB 3.0, GbE) are far below the
line rate they capture: capture is buffered on board and filtered in hardware, not streamed raw.

## What "all USB-C pins" means electrically

The receptacle has 24 pins; after the receptacle's internal ties there are 16 distinct signals
plus power. All of them are captured, and each maps onto a TAP interface (`CHANNEL`) and
record kind from PR #4.

| Pins | Signal | Nature | How it is captured | TAP channel / record |
|---|---|---|---|---|
| A6/A7, B6/B7 | D+ / D− | half-duplex, LS 1.5 / FS 12 / HS 480 Mb/s; tied together in the receptacle | high-impedance differential and single-ended receivers, oversampled in fabric (or ULPI PHY in monitor mode, see below) | ch 0, `PACKET`/`EVENT`, format 0 or 1 |
| A2/A3, B2/B3 | TX1±, TX2± | unidirectional, 5/10/20 Gb/s, or DP main link | passive pick-off to FPGA transceiver RX | ch 1, `PACKET`, formats 2–7, 12 |
| A10/A11, B10/B11 | RX1±, RX2± | unidirectional, same | same | ch 1 |
| A5 | CC1 | BMC 300 kb/s PD, Rp/Rd/Ra DC levels 0–5.5 V, or VCONN 5 V | high-Z buffer → comparator (timing) + ADC (levels) | ch 2, `PD_MESSAGE`, `CC_EVENT`, `ANALOG_SAMPLE` |
| B5 | CC2 / VCONN | same | same | ch 2 |
| A8, B8 | SBU1, SBU2 | DP AUX (1 Mb/s Manchester, differential), USB4 sideband SBTX/SBRX (1 Mb/s), debug UART, audio | high-Z buffers → differential and single-ended comparators + ADC | ch 3, `PACKET` format 11, `MARKER` |
| A4/A9/B4/B9 | VBUS | 5–48 V (EPR), up to 5 A | series shunt, high-side monitor (slow, precise) + fast shunt amplifier (transients) | ch 4, `ANALOG_SAMPLE`, `POWER_SAMPLE_RUN` |
| A1/A12/B1/B12 | GND | | reference | |

Orientation: the tap sits between a host-side receptacle and a device-side connector. Every
conductor is fixed, so the FPGA always sees all four SuperSpeed pairs; which pair carries lane 0
and which is TX from the host's point of view follows from the CC orientation the FPGA decodes
itself. No mux is needed, which is the main reason the tap can be passive. Data role swaps do
not change which end drives a pair.

## Tapping the SuperSpeed pairs

Three ways to get a 5–20 Gb/s pair into an FPGA without breaking the link under test:

**A. Passive pick-off (chosen).** Each pair passes straight through the tap on a controlled
100 Ω differential trace. Immediately at the trace, a high-value series resistor pair (or a
coupled-trace directional coupler) feeds an AC-coupled copy to a transceiver RX. With roughly
200 Ω series into the transceiver's 100 Ω termination the coupled copy is about −14 dB
(≈160 mVppd from an 800 mVppd launch, before channel loss) and the through path loses under
1 dB *est.*; UltraScale+ GTY receivers have CTLE and DFE with sensitivity in the tens of
millivolts and a loss budget above 20 dB, so Gen 1 and Gen 2 have margin and USB4 Gen 3 is
plausible but must be measured. The link partners see each other's real terminations, so
Rx.Detect, LFPS, U1/U2/U3 entry and exit, warm reset, polarity and SSC are all untouched; the
FPGA only receives. Cost: the pick-off stubs must be a few millimetres, the tap must be very
close to the FPGA (FMC is fine to ~12 Gb/s, not at 20), and the DUT's channel budget pays for
the tap plus whatever cable is on each side.

**B. FPGA as in-line regenerator.** The FPGA terminates each pair, recovers the clock and data,
and retransmits on the far side; capture is free because the data is already in fabric. This
is proven for Gen 1 on 7-series GTP by
[enjoy-digital/usb3_pipe](https://github.com/enjoy-digital/usb3_pipe) (LTSSM, LFPS, Rx.Detect
in gateware; "enumeration has only been done on a few hardware setups"). The analyzer becomes a
link partner: it must emulate receiver detection toward both sides, forward LFPS handshakes and
low-power state transitions with the right timing, and for USB4 it must behave as a *USB4
retimer*, which is enumerated through the sideband channel and takes part in link training
(CL_WAKE, SLOS forwarding, RT broadcast and TxFFE negotiation, per
[Cadence](https://community.cadence.com/cadence_blogs_8/b/fv/posts/understanding-usb4-retimers-and-their-role-in-gen2-and-gen3---link-training)).
That is a large, spec-conformance-heavy gateware project before the first packet is decoded,
and the analyzer is no longer transparent (it hides the DUT's real link training from itself).

**C. Commercial retimer plus pick-off.** A USB4 retimer (Intel JHL8040R, Kandou KB8001,
Parade PS8830 class) in line gives a fresh signal budget on the tap side, and A is applied at
the retimer's output. Transparent to protocol, but the retimer needs orientation and mode
configuration (I2C from a PD controller, which the FPGA would have to play), datasheets are
mostly under NDA, and the DUT now trains against the retimer. Keep as the fallback for USB4
Gen 3 if A's eye is not good enough; the tap head reserves the footprint and 0 Ω options.

Decision: **A** for v1 at all speeds, with **C** footprint-reserved. **B** is rejected for an
analyzer, though usb3_pipe remains the best reference for the Gen 1 PCS and LTSSM decode.

## Architecture

```
 host-side              TAP HEAD (passive, orientation-agnostic)                device-side
 USB-C recept. ──┬─ TX1/TX2/RX1/RX2 ──[100Ω through traces]──────────────┬── USB-C recept.
                 │        │ pick-off (−14 dB, AC)        [opt. retimer]   │   or captive plug
                 │        └──── 4 × RX ─────────────► GTY quad (RX only)  │
                 ├─ D+/D− ─────────────────────────────────────────────── ┤
                 │        └──── HS diff rx, SE rx ───► LVDS/ISERDES       │
                 ├─ CC1/CC2 ───────────────────────────────────────────── ┤
                 │        └──── buffers ──► 2× comparator + ADC ─► fabric │
                 ├─ SBU1/SBU2 ─────────────────────────────────────────── ┤
                 │        └──── buffers ──► diff+SE comparators + ADC     │
                 ├─ VBUS ──[2 mΩ shunt]────────────────────────────────── ┤
                 │        └──── INA228 (slow) + INA240 (fast) ─► ADC      │
                 └─ GND ───────────────────────────────────────────────── ┘
                                         │ FMC HPC
                 ┌───────────────────────┴────────────────────────────────┐
                 │ FPGA (Kintex US+ KU5P)                                  │
                 │  PCS/decoders ─► per-channel framers ─► 64-bit 500 MHz  │
                 │  8b10b · 128b132b · 64b66b · RS-FEC · NRZI · BMC · AUX  │  timestamp
                 │  hardware filter (idle/SKP suppression, match/action)   │
                 │  ─► DDR4 ring buffer ─► PCIe DMA (LitePCIe/XDMA)        │
                 │  trigger in/out SMA · 10 MHz/PPS ref in · sync HDMI     │
                 └───────────────────────┬────────────────────────────────┘
                                         │ PCIe Gen3 x8 (or 10GbE SFP+)
                 ┌───────────────────────┴────────────────────────────────┐
                 │ host: Rust (demuxusb-rs) usbtap backend                 │
                 │  capture frames ─► TAP TLVs ─► pcapng (LINKTYPE_USB_TAP)│
                 │  live Wireshark pipe · OS-capture correlation markers   │
                 └─────────────────────────────────────────────────────────┘
```

### Timestamp domain

One free-running 64-bit counter at **500 MHz (2 ns)**, from a low-jitter 100 MHz oscillator,
with an optional external 10 MHz or PPS input that replaces the oscillator reference. Every
channel (USB 2, each SuperSpeed lane, CC, SBU, analog, GPIO, markers) latches this counter.
This is exactly the model `pcapng-usb-spec.md` wants: `TICK_RATE = 500 000 000 / 1`, one IDB
per channel, all IDBs of a session sharing the tick domain via `INTERFACE_IDS`, and `TS_TICKS`
as the value of record. 2 ns matches the Beagle 5000's USB 3 resolution; the Beagle's USB 2
60 MHz tick is coarser than ours by 8×, which the format absorbs because each interface declares
its own rate. The received-data clocks of the lanes are independent (SSC, two directions) and
are *not* the timestamp clock; a packet's `TS_TICKS` is the counter value when its first symbol
left the transceiver's elastic buffer, with a constant, calibrated offset per lane recorded in
the IDB (`if_description`, and a vendor TLV).

Host correlation hooks (spec section "Correlation with OS-level captures"): a host write to a
register produces a `MARKER` record carrying a host-supplied 64-bit value and the tick at which
it was written (method 3, shared marker); a PPS or trigger edge produces the same (method 6,
hardware trigger line); the analyzer's host driver samples host monotonic time against the
device counter periodically for `CLOCK_MODEL` fits.

### Capture pipeline and bandwidth

| Link under test | Raw line rate (both directions) | After hardware idle/SKP suppression, worst case | Comment |
|---|---|---|---|
| USB 2.0 HS | 0.48 Gb/s | < 0.5 Gb/s | trivial |
| USB 3.2 Gen 1x1 | 10 Gb/s | ≈ 8 Gb/s | PCIe Gen 3 x4 suffices |
| USB 3.2 Gen 2x1 | 20 Gb/s | ≈ 19 Gb/s | PCIe Gen 3 x8 (~50 Gb/s practical) |
| USB 3.2 Gen 2x2 | 40 Gb/s | ≈ 39 Gb/s | PCIe Gen 3 x8 |
| USB4 Gen 2x2 / TB3 20 | 41 Gb/s | ≈ 39 Gb/s | PCIe Gen 3 x8 |
| USB4 Gen 3x2 / TB3 40 | 82.5 Gb/s | ≈ 78 Gb/s | exceeds Gen 3 x8; needs x16 (KU5P PCIE4 supports it) or filtering + DDR4 burst buffer |

Sustained bidirectional saturation is rare in practice; the Beagle 5000 and Voyager both rely on
on-board buffer plus hardware filtering. Design rule: the fabric must *decode and filter* at
full line rate on all four lanes simultaneously (no drops in the PCS), the DDR4 ring absorbs
bursts, and the host link drains the filtered stream. Match/action filters (address, endpoint,
packet type, tunnelled protocol, "drop ISO payload beyond N bytes") are implemented in the
framer so that long captures of a busy USB4 link are possible even over a slower host link.

Capture frame (FPGA to host), 16-byte header, 8-byte aligned payload:

```
u8  kind        1 packet, 2 event, 4 pd, 5 cc_event, 6 analog, 7 marker, 8 control, 0x80+ internal
u8  channel     0 usb2, 1 ss, 2 cc, 3 sbu, 4 power, 5 gpio
u16 flags       lane[1:0], direction[3:2], truncated, crc_ok, decode_err, ...
u32 len         payload bytes
u64 ts_ticks    500 MHz counter at first symbol
u8  payload[len], padded to 8
```

The host maps this one-to-one onto TAP pseudo-header TLVs (`TS_TICKS`, `DIRECTION`,
`USB3_LANE`, `USB3_PACKET_TYPE`, `PD_FRAME`, `POWER_SAMPLE`, ...). The FPGA does not emit TLVs
itself; the frame is smaller and the TLV layout can evolve in software.

### Per-channel front ends

**USB 2.0.** Two options, both on the tap head:

1. *Direct sampling (primary).* A high-impedance differential receiver on D+/D− (HS swing
   400 mV into the bus's own 45 Ω terminations) and two single-ended receivers for SE0, chirp
   and LS/FS levels, into FPGA LVDS inputs oversampled at ≥ 960 MS/s with ISERDES (UltraScale+
   ISERDES runs to 1.6 Gb/s). NRZI, bit-unstuffing, SYNC and EOP detection in fabric. Gives
   `USB2_EOP_INFO` and payload format 1 (with SYNC) which a ULPI PHY cannot, and keeps the
   stub on the bus to a few millimetres. This is how the Beagle class works.
2. *ULPI PHY in monitor mode (fallback).* A USB334x PHY wired in parallel to the bus with its
   terminations off, as OpenVizsla, LambdaConcept USB2Sniffer and Cynthion do. Known to work,
   cheap, but adds the PHY's own stub and loses sub-bit timing.

**CC1 / CC2.** Each line: 20 V-tolerant protection, > 500 kΩ buffer (so Rp/Rd/Ra sensing is
not disturbed), then a fast comparator with a programmable threshold (BMC edge timing to the
2 ns tick) and a 12-bit ≥ 2 MS/s ADC (termination levels, VCONN presence, `CC_STATE`, and raw
BMC capture as `PD_RAW_BMC` when wanted). BMC decode, 4b5b, SOP* detection and CRC32 in fabric;
GoodCRC pairing in fabric so `goodcrc_ticks` is exact. Optional Rd/Rp injection is deliberately
*not* on the tap head (keeps it passive; a Twinkie does that job).

**SBU1 / SBU2.** Same high-impedance buffers to ADC (0–5 V) plus one differential comparator
(DP AUX Manchester) and two single-ended comparators (USB4 SBTX/SBRX, UART). Decoders: AUX
transactions (payload format 11 reuses `USB4_SIDEBAND` kind for sideband; AUX gets a vendor
format until the spec grows one), USB4 sideband LT/AT transactions, raw UART bytes.

**VBUS / VCONN.** A 2 mΩ shunt in the VBUS through path (5 A, 48 V EPR rated), an INA228 class
monitor (20-bit, ~kS/s, precise) and an INA240 class 80 V common-mode shunt amplifier into the
ADC for µs-scale transients around PD contract changes. VCONN current via a small shunt on
whichever CC carries it. Emitted as `POWER_SAMPLE_RUN` at a configurable rate.

**SuperSpeed.** Four GTY channels, RX only, in one quad with a shared reference clock. Per lane:
rate detection (LFPS/training set analysis in fabric, or follow the CC/sideband negotiated
mode), 8b/10b (Gen 1, DP HBR), 128b/132b (USB 3.2 Gen 2, USB4 Gen 3, DP UHBR), 64b/66b (USB4
Gen 2, TB3), descrambling, optional RS-FEC (USB4 Gen 2/3: 12 × 16 B symbols, 2 B sync, 4 B FEC
per 198 B block), then protocol framers: USB3 link layer (LMP/TP/DPH/DPP/ITP, link commands,
ordered sets, LTSSM tracking to raise `USB3_LTSSM` events), USB4 transport layer (HopID /
PDF routing, tunnelled USB3, PCIe, DP), DP main link (MSA, SDP). LFPS is seen by the
transceiver as electrical-idle entry/exit; the gateware timestamps the bursts to produce
`USB3_LFPS` records.

### Host side

* **PCIe** (primary): the FPGA is a PCIe Gen 3 x8 endpoint with DMA into a host ring (LitePCIe
  or AMD XDMA; both have Linux drivers). A Linux capture host is assumed; a Thunderbolt PCIe
  enclosure makes this usable from a laptop. The Rust backend in this repo consumes the ring,
  writes pcapng (`.pcapng.zst` recommended per the spec's open question 12), and can feed a
  live pipe to Wireshark with the TAP Lua dissector.
* **10 GbE SFP+** (optional, standalone box): the same frames in UDP; useful when the DUT host is
  also the capture host and PCIe is awkward, and for multi-analyzer setups.
* Triggers: SMA in/out at the tick domain; HDMI-style sync between analyzers as the Beagle does.

## Parts

Transceiver requirement per generation (per lane, NRZ unless stated):

| Link | Rate | Coding | Minimum transceiver |
|---|---|---|---|
| USB 3.2 Gen 1, DP HBR/HBR2 | 5 / 2.7 / 5.4 Gb/s | 8b/10b | Artix-7 GTP (6.6), anything newer |
| USB 3.2 Gen 2, DP HBR3, UHBR10 | 10 / 8.1 / 10 Gb/s | 128b/132b, 8b/10b | ≥ 10.3 Gb/s: CertusPro-NX, Artix US+ GTH, Agilex 5 |
| USB4 Gen 2, TB3 20 | 10 / 10.3125 Gb/s | 64b/66b | same |
| USB4 Gen 3, TB3 40, DP UHBR20 | 20 / 20.625 / 20 Gb/s | 128b/132b (+RS-FEC) | ≥ 21 Gb/s: Kintex US+ GTY (FFVB676 or larger package), Agilex 5 group A (28.1) |
| USB4 Gen 4 | 25.6 GBaud PAM-3 | 11b/7t + RS-FEC | none |

Candidate FPGAs:

| Device | Transceivers | PCIe | Covers | Notes |
|---|---|---|---|---|
| Lattice CertusPro-NX LFCPNX-100 | 8 × 10.3 Gb/s | Gen 3 x4 hard | Gen 1/2, USB4 Gen 2 | open-ish toolchain pressure, LPDDR4; 100K LUT may be tight for 4 lanes of 128b/132b plus framers |
| AMD Artix UltraScale+ AU15P / AU25P | 12 × GTH or GTY, 16.3 Gb/s only in FFVB676 (12.5 otherwise) | Gen 4 x8 hard | Gen 1/2, USB4 Gen 2, DP HBR3 | good mid tier; Avnet AUBoard-15P and Alinx AXAU15 boards exist |
| AMD Kintex UltraScale+ KU3P / KU5P | 16 × GTY 32.75 Gb/s (FFVB676 and larger; A676/B784 are rate-limited) | Gen 3 x16 hard, KU5P adds 100G MAC | everything except Gen 4 | chip alone ≈ ¥483k (~$3.2k) at 52-week lead from distribution ([Farnell JP](https://jp.farnell.com/en-JP/amd/xcku3p-l2ffvb676e/fpga-kintex-ultrascale-fcbga-676/dp/3132207)); complete Alinx AXKU5 board (KU5P-2FFVB676I, 16 GTY, PCIe Gen 3 x8, FMC HPC, 256 MB DDR4) listed at £1,026 ([fpgadeveloper](https://boards.fpgadeveloper.com/boards/AXKU5)) |
| Altera Agilex 5 E-series (group A) | up to 28.1 Gb/s | Gen 4 x4 hard | everything except Gen 4 | dev kits ≈ $1–2k; toolchain and open-source IP ecosystem thinner than AMD's for this job |

Selection guide figures from the
[UltraScale+ product selection guide](https://www.mouser.lt/pdfDocs/ultrascale-plus-fpga-product-selection-guide-5.pdf),
[CertusPro-NX](https://www.latticesemi.com/en/Products/FPGAandCPLD/CertusPro-NX) and
[Agilex 5 overview](https://www.intel.com/content/www/us/en/docs/programmable/762191/current/transceivers-in-fpgas-and-socs.html).

**Choice: KU5P on an Alinx AXKU5 (or AMD KCU116) for phase 1.** It is the cheapest way to get
32 Gb/s GTY, enough fabric for four lanes of decode, PCIe DMA and DDR4 in one purchase, and it
does not have to be re-bought for USB4 Gen 3. Two caveats to verify before ordering: which GTY
quads are routed to the FMC HPC (the board page lists the FMC and PCIe but not the lane map),
and that the FMC's 1.8 V fixed VADJ suits the tap head (it does; the tap head's digital side is
1.8 V LVDS and SPI).

If budget matters more than USB4 headroom, the Artix UltraScale+ AU15P path (AUBoard-15P or
AXAU15, FFVB676 for 16.3 Gb/s) does USB 3.2 Gen 2 and USB4 Gen 2 for roughly half the board
price; the tap head is the same.

Tap head BOM (phase 1, *est.* single quantity):

| Block | Parts | Cost |
|---|---|---|
| Connectors | 2 × USB-C receptacle (USB4 40 Gb/s rated, 5 A), or 1 receptacle + captive 0.2 m cable | $10 |
| SS pick-off | 8 × precision 0402 resistors, 8 × 100 nF 0201, optional retimer footprint (unpopulated) | $5 |
| USB 2 front end | high-speed differential comparator (ADCMP60x class), 2 × SE comparators, ESD | $25 |
| CC/SBU front end | 4 × high-Z buffer op amps, 5 × comparators, 8-ch 12-bit 2–5 MS/s ADC | $40 |
| VBUS/VCONN | 2 mΩ shunt, INA228, INA240, dividers | $15 |
| Clocking | 100 MHz low-jitter oscillator, reference clock buffer for GTY quad, 10 MHz/PPS input | $30 |
| I/O | 2 × SMA, HDMI-style sync, LEDs | $15 |
| FMC HPC connector, power, ESD | | $40 |
| PCB | 10–12 layer, low-loss laminate (Megtron 6 or equivalent), controlled impedance, 5 pcs | $600–1,200 |
| Assembly | 5 pcs | $500–1,000 |
| **Total, 5 tap heads** | | **≈ $1,500–2,500** |

Whole phase 1 kit: ≈ £1,000 FPGA board + tap heads + a Linux host with a free x8 slot (or a
Thunderbolt enclosure): **under $4,000**, against $6,000 for a Beagle 5000 v2 that has no
Type-C, no PD and no Gen 2.

## Gateware and software plan

Toolchain: LiteX/Migen for the SoC glue (LitePCIe, LiteDRAM, transceiver wrappers for GTH/GTY
exist and are maintained), Amaranth for the protocol cores where it helps (LUNA/Cynthion's USB
2 analyzer is Amaranth and is the reference for the USB 2 path), Vivado for the KU5P.
References to lift from: usb3_pipe (8b/10b PCS, LTSSM model, LFPS detection), Daisho
(link-layer framing), Cynthion `usb_analyzer` (USB 2 capture and host streaming), sigrok's
`usb_power_delivery` decoder (BMC/4b5b/PD framing), LiteX `liteeth` for the SFP+ path.

Milestones, each ending in a pcapng file the Rust side reads:

1. **Platform** (1 month). KU5P board bring-up with LitePCIe DMA and DDR4 ring; capture-frame
   path with synthetic frames; the 500 MHz tick; Rust `usbtap` backend writing pcapng TAP
   `CAPTURE_CONTROL` and `MARKER` records. Verifies the host link and timestamps end to end
   before any front end exists.
2. **Tap head rev A** (2–3 months, parallel to 1). Schematic, layout, fabrication; bench
   verification that a Gen 2 link trains through it and that the pick-off eyes are open at the
   FMC (this is the go/no-go for architecture A).
3. **USB 2 + PD + analog + SBU** (2–3 months). Direct-sampled USB 2 capture, BMC/PD decode,
   `CC_STATE` and power sampling, SBU raw capture. At this point the device already does what
   no open tool does: one tick domain across USB 2, PD and power on a Type-C link.
4. **USB 3.2 Gen 1** (2–3 months). 8b/10b PCS on GTY, descrambling, link-layer framer, LTSSM
   and LFPS events, hardware idle suppression, match/action filters. Beagle 5000 parity.
5. **Gen 2 and DP Alt Mode** (2 months). 128b/132b, rate switching, DP AUX and main link
   framing.
6. **USB4 Gen 2/3** (4–6 months, phase 2 hardware if the FMC eye is not good enough at 20 Gb/s).
   64b/66b and 128b/132b with RS-FEC, sideband decode, transport-layer framer, tunnelled
   protocol demux, PCIe Gen 3 x16 or x8 + heavier filtering.

Roughly 9–12 months of focused part-time work to Beagle 5000 parity on a Type-C link
(milestone 4); USB4 is a second project of similar size on top.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Passive pick-off eye too closed at Gen 2 / USB4 Gen 3 | no capture at that rate | measure at milestone 2 with a scope and the GTY eye scan; shorten stubs, change coupling ratio, fall back to architecture C (retimer footprint is on the board) |
| Tap plus two cables exceeds the DUT's channel budget (link trains at a lower rate or not at all through the analyzer) | analyzer perturbs what it measures | captive short cable on one side; document the loss; this is the same compromise every in-line analyzer makes |
| FMC HPC bandwidth at 20 Gb/s | USB4 Gen 3 on phase 1 hardware fails | phase 2 integrated board (FMC+ or FPGA adjacent to connectors); the USB4 gateware is unaffected |
| GTY to FMC lane map on the Alinx board | wrong board | confirm from the schematic before ordering; KCU116 is the known-good alternative at ~3× the price |
| Rate autodetect on a passive tap (the FPGA is not told the negotiated speed) | missed start of link training | run all four RX at the highest rate with the CDR free, detect TS1/TS2 symbol rate from the recovered data; also follow PD/sideband negotiation; record Polling.LFPS from electrical-idle timing regardless |
| USB4 protocol work (RS-FEC, transport layer, sideband) is large and specs are 1,000+ pages | schedule | USB4 and TB3 specs are public; defer to milestone 6; the format already has provisional slots |
| 128b/132b and 64b/66b decode plus RS-FEC on four lanes at 20 Gb/s in fabric | timing closure | 128-bit datapath at 160 MHz per lane is routine on UltraScale+; RS decoder is the heaviest block and can be bypassed (FEC is optional in Gen 2/3) |
| PCIe host only | laptop users | 10 GbE SFP+ output as a second-class path; or a small Linux capture box |
| Part availability (KU5P 52-week distributor lead) | schedule | buy a complete board, not the chip; AU15P boards as the budget alternative |

## Open decisions

1. **Form factor of the device side:** second receptacle (flexible, two cables in the channel)
   or captive plug (less loss, fixed length). Recommendation: receptacle on rev A for
   flexibility; captive on the integrated board.
2. **USB 2 front end:** direct sampling only, or also populate a ULPI PHY footprint as insurance.
   Recommendation: both footprints on rev A, populate the PHY on two of five boards.
3. **FPGA board:** Alinx AXKU5 (cheapest GTY) versus AUBoard-15P/AXAU15 (half the price, no USB4
   Gen 3 path). Recommendation: AXKU5, after checking the FMC lane map.
4. **Host link:** PCIe first. Add SFP+ only if a standalone box is wanted.
5. **Repository:** this document lives here because the output format does; gateware and
   hardware should get their own repository (KiCad, LiteX/Amaranth), with this repo providing
   the `usbtap` capture backend and the pcapng writer. The new repository has to be created by
   the owner.
6. **Name.** The spec calls the link type `USB_TAP`; "usbtap" is the obvious working name for
   the hardware.

## What this would give the format work

Several of PR #4's open questions get answered by having the device: question 7 (USB 3 TLVs
need a real capture), 8 (PD source), 10 (`TICK_RATE` in every header, decided no, since the
device's 500 MHz rate is per IDB), and the correlation blocks get a first writer that emits
`CLOCK_ANCHOR` method 6 from a real trigger line. The record kinds `CC_EVENT`,
`ANALOG_SAMPLE` and payload format 11 (USB4 sideband) were specified without hardware; the tap
head is the hardware.

## References

* Total Phase Beagle USB 5000 v2: <https://totalphase.com/products/beagle-usb5000-v2-usb2>
* Teledyne LeCroy Voyager M4x: <https://www.teledynelecroy.com/protocolanalyzer/usb/usb-voyager-m4x>
* Great Scott Gadgets Cynthion: <https://www.adafruit.com/product/6005>, <https://greatscottgadgets.com/cynthion>
* Twinkie USB-PD sniffer: <https://www.chromium.org/chromium-os/developer-library/guides/hardware-schematics/twinkie>
* enjoy-digital usb3_pipe (USB3 PIPE on FPGA transceivers): <https://github.com/enjoy-digital/usb3_pipe>
* LambdaConcept USB2 sniffer: <https://github.com/lambdaconcept/usbsniffer>
* USB4 generations and coding (Wikipedia summary of the USB4 spec): <https://en.wikipedia.org/wiki/USB4>
* Synopsys, PAM-3 for USB4 v2: <https://www.synopsys.com/articles/pam3-technology-implementation-usb4-v2.html>
* Cadence, USB4 retimers in Gen 2/Gen 3 link training: <https://community.cadence.com/cadence_blogs_8/b/fv/posts/understanding-usb4-retimers-and-their-role-in-gen2-and-gen3---link-training>
* AMD UltraScale+ product selection guide: <https://www.mouser.lt/pdfDocs/ultrascale-plus-fpga-product-selection-guide-5.pdf>
* Lattice CertusPro-NX: <https://www.latticesemi.com/en/Products/FPGAandCPLD/CertusPro-NX>
* Altera Agilex 5 device overview, transceivers: <https://www.intel.com/content/www/us/en/docs/programmable/762191/current/transceivers-in-fpgas-and-socs.html>
* Alinx AXKU5 board summary: <https://boards.fpgadeveloper.com/boards/AXKU5>
* XCKU3P distributor listing (price, lead time): <https://jp.farnell.com/en-JP/amd/xcku3p-l2ffvb676e/fpga-kintex-ultrascale-fcbga-676/dp/3132207>
* [`pcapng-usb-spec.md`](pcapng-usb-spec.md) (PR #4) and [`tdc-format.md`](tdc-format.md)
