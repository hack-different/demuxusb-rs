import os
import struct
from pathlib import Path

import pytest

import demuxusb

REPO = Path(__file__).resolve().parents[3]
TESTDATA = Path(os.environ.get("DEMUXUSB_TESTDATA", REPO / "ext" / "testdata"))
FT230X = TESTDATA / "serial" / "ftdi" / "FT230X_Basic_UART_w7_init.tdc"

BLOCK_SIZE = 1 << 20


def build_file(stream: bytes) -> bytes:
    """Wraps an uncompressed stream in a .tdc container using literal-only FastLZ blocks."""
    header = bytearray(0x1A8)
    header[0:4] = b"TPDC"
    header[4:6] = b"\x00\x03"
    header[6:8] = struct.pack("<H", 0x1A8)
    header[0x14:0x16] = struct.pack("<H", 0x10A)
    header[0x26:0x28] = struct.pack("<H", 2)
    header[0x28:0x30] = bytes([3, 0, 0, 0, 1, 0, 0x0B, 3])
    out = bytearray(header)
    for start in range(0, len(stream), BLOCK_SIZE):
        block = stream[start : start + BLOCK_SIZE]
        compressed = bytearray()
        for i in range(0, len(block), 32):
            literal = block[i : i + 32]
            compressed.append(len(literal) - 1)
            compressed += literal
        out.append(0)
        out += struct.pack("<I", len(compressed))[:3]
        out += bytes(4)
        out += compressed
    return bytes(out)


def capture_entry(id: int) -> bytes:
    return (
        bytes([0x05])
        + struct.pack("<IIIIQI", id, 3, 1_414_535_317, 1_414_535_400, 120_000_000, 60_000_000)
        + bytes(16)
    )


def packet_record(sequence: int, timestamp: int, data: bytes) -> bytes:
    elements = bytes([0x00, 3, 10, 0, 0, 0, 0x03, 0, 0xFF, 0xFF])
    elements += bytes([0x0B, 3]) + struct.pack("<III", 14 + len(data), 0, len(data)) + data
    record = bytes([0x10]) + struct.pack("<HB", 30 + len(elements), 0)
    record += struct.pack("<III", sequence, 0, 20) + bytes([1, 0])
    record += struct.pack("<QI", timestamp, 45)
    return record + elements


def synthetic(count: int = 10) -> bytes:
    stream = capture_entry(1)
    for i in range(count):
        stream += packet_record(i, i * 60, bytes([0x69, i & 0x7F, 0x10]))
    stream += bytes([0x06, 3, 0, 0, 0, 2, 0, 0, 0, 0xAA, 0xBB])
    return build_file(stream)


def test_parses_synthetic_file():
    tdc = demuxusb.TdcFile.parse(synthetic())
    assert tdc.header.format_version == 0x10A
    assert tdc.header.element_types == [(3, 0, 0), (1, 11, 3)]
    assert len(tdc.captures) == 1
    assert tdc.last_capture().ticks_per_second == 60_000_000
    assert tdc.footer.version == 3
    assert tdc.footer.data == b"\xaa\xbb"

    records = list(tdc)
    assert [r.sequence for r in records] == list(range(10))
    r = records[3]
    assert r.packet_data == b"\x69\x03\x10"
    assert r.timestamp == 180
    assert r.time_ns == 3_000
    assert r.absolute_time_ns == 1_414_535_317 * 10**9 + 3_000
    assert r.duration_ns == 750
    assert r.speed == "FS"
    assert r.device_index is None
    assert r.pid is None  # the synthetic records carry no packet-info element
    assert [e["type"] for e in r.elements] == ["status", "packet"]
    assert r.elements[1] == {"tag": 0x0B, "type": "packet", "status": 0, "data": b"\x69\x03\x10"}


def test_records_iterator_is_lazy_and_restartable():
    tdc = demuxusb.TdcFile.parse(synthetic(5))
    it = tdc.records()
    assert next(it).sequence == 0
    assert next(it).sequence == 1
    assert len(list(tdc.records())) == 5
    assert len(list(it)) == 3


def test_pcapng_export(tmp_path):
    tdc = demuxusb.TdcFile.parse(synthetic(4))
    out = tmp_path / "out.pcapng"
    assert tdc.write_pcapng(out) == 4
    assert out.read_bytes() == tdc.to_pcapng()
    assert tdc.to_pcapng()[:4] == b"\x0a\x0d\x0d\x0a"
    assert tdc.write_pcapng(out, capture=2) == 0


def test_errors():
    with pytest.raises(demuxusb.TdcFormatError, match="not a Data Center file"):
        demuxusb.TdcFile.parse(b"XXXX" + bytes(100))
    with pytest.raises(ValueError):
        demuxusb.TdcFile.parse(b"TPDC")
    with pytest.raises(OSError):
        demuxusb.TdcFile("/does/not/exist.tdc")


@pytest.mark.skipif(not FT230X.exists(), reason="USBTraces testdata not checked out")
def test_real_capture():
    tdc = demuxusb.TdcFile(FT230X)
    assert [c.id for c in tdc.captures] == [1, 2]
    records = list(tdc)
    packets = tdc.packets()
    assert len(packets) == sum(1 for r in records if r.packet_data is not None)
    assert tdc.write_pcapng(os.devnull) == len(packets)
    assert all(p.speed == "FS" for p in packets)
