"""Readers for Total Phase USB analyzer captures (Data Center .tdc files)."""

from collections.abc import Iterator
from os import PathLike
from typing import Any, Optional, Union

__version__: str

_Path = Union[str, PathLike[str]]

class TdcFormatError(ValueError):
    """The data is not a valid .tdc file, or uses a structure the reader does not understand."""

class Header:
    signature_version: tuple[int, int]
    header_len: int
    writer_version: tuple[int, int]
    saved_at: int
    format_version: int
    element_types: list[tuple[int, int, int]]
    """`(version, tag, kind)` for each element type the record stream uses."""
    raw: bytes

class Capture:
    id: int
    kind: int
    started_at: int
    stopped_at: int
    duration_ticks: int
    ticks_per_second: int
    extra: bytes
    @property
    def duration_ns(self) -> int: ...
    def ticks_to_ns(self, ticks: int) -> int: ...
    def absolute_time_ns(self, ticks: int) -> int: ...

class Footer:
    version: int
    data: bytes

class Record:
    offset: int
    flags: int
    sequence: int
    nested: bool
    reserved: int
    capture: int
    capture_flags: int
    timestamp: int
    """Start time in analyzer ticks since the start of the capture."""
    duration: int
    time_ns: Optional[int]
    absolute_time_ns: Optional[int]
    duration_ns: Optional[int]
    elements: list[dict[str, Any]]
    """Every element as a dict with `type` (e.g. "status", "packet") and `tag` keys."""
    packet_data: Optional[bytes]
    """Raw USB packet (PID, payload, CRC) when the record is a single packet."""
    speed: Optional[str]
    """"LS", "FS" or "HS"."""
    error: bool
    device_index: Optional[int]
    pid: Optional[int]
    address: Optional[int]
    endpoint: Optional[int]
    direction_in: Optional[bool]
    comment: Optional[str]
    bus_event: Optional[int]
    children: list[int]

class RecordIterator(Iterator[Record]):
    def __iter__(self) -> RecordIterator: ...
    def __next__(self) -> Record: ...

class TdcFile:
    """A Data Center capture, fully decompressed in memory."""

    def __init__(self, path: _Path) -> None: ...
    @staticmethod
    def open(path: _Path) -> TdcFile: ...
    @staticmethod
    def parse(data: bytes) -> TdcFile: ...
    @property
    def header(self) -> Header: ...
    @property
    def captures(self) -> list[Capture]: ...
    @property
    def footer(self) -> Optional[Footer]: ...
    @property
    def block_levels(self) -> list[int]: ...
    def stream(self) -> bytes: ...
    def capture(self, id: int) -> Optional[Capture]: ...
    def last_capture(self) -> Optional[Capture]: ...
    def records(self) -> RecordIterator: ...
    def __iter__(self) -> RecordIterator: ...
    def packets(self, capture: Optional[int] = None) -> list[Record]: ...
    def write_pcapng(self, path: _Path, capture: Optional[int] = None) -> int: ...
    def to_pcapng(self, capture: Optional[int] = None) -> bytes: ...
