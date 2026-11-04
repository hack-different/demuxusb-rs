# Python and Ruby bindings

Both bindings wrap the native Data Center `.tdc` reader in `src/tdc` (see
`docs/tdc-format.md`) and expose the same API: open a capture, iterate its records lazily, read
packet bytes and timestamps, and export to pcapng for Wireshark's `usbll` dissector.

## Python (`bindings/python`, PyO3 + maturin)

```sh
cd bindings/python
pip install maturin
maturin develop            # or: maturin build --release
```

```python
import demuxusb

tdc = demuxusb.TdcFile("capture.tdc")
print(tdc.header.format_version, [c.id for c in tdc.captures])
for record in tdc:                       # lazy
    if record.packet_data is not None:
        print(record.time_ns, record.speed, record.pid, record.packet_data.hex())
tdc.write_pcapng("capture.pcapng", capture=tdc.last_capture().id)
```

Records expose the raw fields (`sequence`, `capture`, `timestamp`, `duration`, ...), converted
times (`time_ns`, `absolute_time_ns`, `duration_ns`), shortcuts (`speed`, `pid`, `address`,
`endpoint`, `direction_in`, `error`, `comment`, `bus_event`, `children`) and every decoded
element as a dict (`record.elements`). Malformed files raise `demuxusb.TdcFormatError` (a
`ValueError`); I/O failures raise `OSError`. Type stubs are in `demuxusb.pyi`.

Tests: `pip install pytest && pytest tests`.

## Ruby (`bindings/ruby`, magnus + rb-sys)

```sh
cd bindings/ruby
bundle install
bundle exec rake compile   # builds lib/demuxusb/demuxusb.so
bundle exec rake test
```

```ruby
require "demuxusb"

tdc = Demuxusb::TdcFile.open("capture.tdc")
tdc.each_record do |record|              # lazy; TdcFile is Enumerable
  next unless record.packet?
  puts "#{record.time_ns} #{record.speed} #{record.packet_data.unpack1('H*')}"
end
tdc.write_pcapng("capture.pcapng", capture: tdc.last_capture.id)
```

Same accessors as Python; predicates are `packet?`, `nested?` and `error?`, the header and
footer are Hashes, and elements are Hashes with symbol keys (`{type: :packet, tag: 11, ...}`).
Packet bytes are binary (`ASCII-8BIT`) Strings. Malformed files raise `Demuxusb::FormatError`
(a `Demuxusb::Error`); I/O failures raise `IOError`.

## Test captures

Both test suites build synthetic files and also check a real capture from the USBTraces
collection when it is present at `ext/testdata` (or wherever `DEMUXUSB_TESTDATA` points).

## Publishing

Order matters, because the gem's extension depends on the published crate:

1. `cargo publish` at the repository root (crate `demuxusb-rs`). Run `cargo publish --dry-run` first.
2. `cd bindings/ruby && gem build demuxusb.gemspec && gem push demuxusb-0.1.0.gem`. This is a
   source gem, so installing it compiles the extension and needs a Rust toolchain.
3. Optional, PyPI: `cd bindings/python && maturin publish`. CI-built wheels for each platform
   are better long term.

Inside this repository the root `Cargo.toml` patches `demuxusb-rs` to the local copy, so the
bindings always build against the code next to them.

## Not covered yet

The older CSV + `.bin` reader (`total_phase_parser`) is not bound: it borrows across packets
and is being superseded by the `.tdc` reader.
