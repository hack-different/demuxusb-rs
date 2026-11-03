# demuxusb-rs

A Rust port of [demuxusb](https://github.com/hack-different/demuxusb): tools for reading USB captures
from Total Phase Beagle analyzers and turning them into something other tools can use.

It reads two formats:

- **Data Center `.tdc` captures** — the files Total Phase Data Center saves. The format is
  undocumented; [`docs/tdc-format.md`](docs/tdc-format.md) describes it as reverse-engineered here,
  with a confidence label on each field.
- **Exported streams** — Data Center's `.bin` + `.csv` export.

## Usage

```sh
cargo run -- tdc-info  capture.tdc            # header, capture table and record statistics
cargo run -- tdc-dump  capture.tdc            # every record, one per line
cargo run -- tdc-pcap  capture.tdc out.pcapng # USB packets as pcapng (USB 2.0 link layer)
cargo run -- tree      capture                # exported stream (capture.bin + capture.csv) as a tree
cargo run -- pcap      capture out.pcap       # exported stream to pcap
```

## Tests

```sh
git submodule update --init   # ext/testdata: captures from the USBTraces collection
cargo test
```

`tests/test_tdc.rs` checks the `.tdc` reader against every capture in `ext/testdata` and skips
those checks when the data isn't checked out; `tests/test_parse.rs` needs it.

CI (`.github/workflows/ci.yml`) builds every target and runs the unit tests and the tests that
don't need captures on each push to `main` and each pull request.

## Contributing

Pull requests are either a **plan / design doc** (under `docs/`, labelled `plan`, merged on a light
read so it's visible for review) or **code** (with the verification filled in). The pull request
template asks which.
