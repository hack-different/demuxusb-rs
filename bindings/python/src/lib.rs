//! Python bindings for the Total Phase readers in `demuxusb-rs`.
//!
//! ```python
//! import demuxusb
//!
//! tdc = demuxusb.TdcFile("capture.tdc")
//! for record in tdc:
//!     if record.packet_data is not None:
//!         print(record.time_ns, record.speed, record.packet_data.hex())
//! tdc.write_pcapng("capture.pcapng")
//! ```

use demuxusb_rs::tdc::{self, Element, Record, Speed, TdcError};
use pyo3::create_exception;
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::path::PathBuf;

create_exception!(
    demuxusb,
    TdcFormatError,
    PyValueError,
    "The data is not a valid Data Center .tdc file, or uses a structure the reader does not understand."
);

fn to_py_err(err: TdcError) -> PyErr {
    match err {
        TdcError::Io(io) => PyOSError::new_err(io.to_string()),
        other => TdcFormatError::new_err(other.to_string()),
    }
}

fn speed_name(speed: Speed) -> Option<String> {
    match speed {
        Speed::Unknown => None,
        other => Some(other.to_string()),
    }
}

/// The uncompressed header of a .tdc file.
#[pyclass(name = "Header", module = "demuxusb", frozen, get_all)]
struct PyHeader {
    /// Bytes 4..6 of the file, always `00 03` so far.
    signature_version: (u8, u8),
    header_len: u16,
    /// Plausibly the version and build of the Data Center release that wrote the file.
    writer_version: (u16, u16),
    /// Unix time the file was saved.
    saved_at: u32,
    format_version: u16,
    /// `(version, tag, kind)` for each element type the record stream uses.
    element_types: Vec<(u16, u8, u8)>,
    raw: Py<PyBytes>,
}

#[pymethods]
impl PyHeader {
    fn __repr__(&self) -> String {
        format!(
            "Header(format_version={:#x}, saved_at={}, element_types={})",
            self.format_version,
            self.saved_at,
            self.element_types.len()
        )
    }
}

/// One capture session. Records refer to it by `Record.capture`.
#[pyclass(name = "Capture", module = "demuxusb", frozen, get_all)]
#[derive(Clone)]
struct PyCapture {
    id: u32,
    kind: u32,
    /// Unix time the capture started.
    started_at: u32,
    /// Unix time the capture stopped.
    stopped_at: u32,
    duration_ticks: u64,
    ticks_per_second: u32,
    extra: Vec<u8>,
}

impl From<&tdc::Capture> for PyCapture {
    fn from(c: &tdc::Capture) -> Self {
        PyCapture {
            id: c.id,
            kind: c.kind,
            started_at: c.started_at,
            stopped_at: c.stopped_at,
            duration_ticks: c.duration_ticks,
            ticks_per_second: c.ticks_per_second,
            extra: c.extra.clone(),
        }
    }
}

impl PyCapture {
    fn inner(&self) -> tdc::Capture {
        tdc::Capture {
            id: self.id,
            kind: self.kind,
            started_at: self.started_at,
            stopped_at: self.stopped_at,
            duration_ticks: self.duration_ticks,
            ticks_per_second: self.ticks_per_second,
            extra: Vec::new(),
        }
    }
}

#[pymethods]
impl PyCapture {
    /// Converts analyzer ticks to nanoseconds.
    fn ticks_to_ns(&self, ticks: u64) -> u128 {
        self.inner().ticks_to_duration(ticks).as_nanos()
    }

    /// Nanoseconds since the Unix epoch of a timestamp (in ticks) in this capture.
    fn absolute_time_ns(&self, ticks: u64) -> u128 {
        self.inner().absolute_time(ticks).as_nanos()
    }

    /// Length of the capture in nanoseconds.
    #[getter]
    fn duration_ns(&self) -> u128 {
        self.ticks_to_ns(self.duration_ticks)
    }

    fn __repr__(&self) -> String {
        format!(
            "Capture(id={}, started_at={}, duration_ticks={})",
            self.id, self.started_at, self.duration_ticks
        )
    }
}

/// The section after the last record (device table and statistics), kept raw.
#[pyclass(name = "Footer", module = "demuxusb", frozen, get_all)]
struct PyFooter {
    version: u32,
    data: Py<PyBytes>,
}

/// One record of the capture: a packet, a transaction, a bus event, a comment, ...
#[pyclass(name = "Record", module = "demuxusb", frozen)]
struct PyRecord {
    record: Record,
    capture: Option<tdc::Capture>,
}

fn element_to_dict<'py>(py: Python<'py>, element: &Element) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("tag", element.tag())?;
    let kind = match element {
        Element::Status(s) => {
            d.set_item("raw", s.raw)?;
            d.set_item("speed", speed_name(s.speed))?;
            d.set_item("error", s.error)?;
            d.set_item("reserved", s.reserved)?;
            d.set_item("device_index", s.device_index)?;
            "status"
        }
        Element::CaptureStarted => "capture_started",
        Element::BusRecord => "bus_record",
        Element::PacketInfo(p) => {
            d.set_item("pid", p.pid)?;
            d.set_item("kind", p.kind)?;
            d.set_item("address", p.address)?;
            d.set_item("endpoint", p.endpoint)?;
            d.set_item("direction_in", p.direction_in)?;
            "packet_info"
        }
        Element::GroupInfo {
            raw,
            address,
            endpoint,
            direction_in,
        } => {
            d.set_item("raw", PyBytes::new(py, raw))?;
            d.set_item("address", address)?;
            d.set_item("endpoint", endpoint)?;
            d.set_item("direction_in", direction_in)?;
            "group_info"
        }
        Element::GroupCount { count, reserved } => {
            d.set_item("count", count)?;
            d.set_item("reserved", reserved)?;
            "group_count"
        }
        Element::SofGroup {
            count,
            reserved,
            flags,
            first_frame,
            last_frame,
        } => {
            d.set_item("count", count)?;
            d.set_item("reserved", reserved)?;
            d.set_item("flags", flags)?;
            d.set_item("first_frame", first_frame)?;
            d.set_item("last_frame", last_frame)?;
            "sof_group"
        }
        Element::Packet { status, data } => {
            d.set_item("status", status)?;
            d.set_item("data", PyBytes::new(py, data))?;
            "packet"
        }
        Element::Transaction { kind, children } => {
            d.set_item("kind", kind)?;
            d.set_item("children", children)?;
            "transaction"
        }
        Element::BusEvent {
            code,
            flags,
            reserved,
        } => {
            d.set_item("code", code)?;
            d.set_item("flags", flags)?;
            d.set_item("reserved", reserved)?;
            "bus_event"
        }
        Element::ChildList {
            count, children, ..
        } => {
            d.set_item("count", count)?;
            d.set_item("children", children)?;
            "child_list"
        }
        Element::Comment(text) => {
            d.set_item("text", text)?;
            "comment"
        }
        Element::Flag(_) => "flag",
        Element::Unknown { data, .. } => {
            d.set_item("data", PyBytes::new(py, data))?;
            "unknown"
        }
    };
    d.set_item("type", kind)?;
    Ok(d)
}

#[pymethods]
impl PyRecord {
    /// Offset of the record in the decompressed stream.
    #[getter]
    fn offset(&self) -> usize {
        self.record.offset
    }
    #[getter]
    fn flags(&self) -> u8 {
        self.record.flags
    }
    /// Sequence number, contiguous from 0 across every capture in the file.
    #[getter]
    fn sequence(&self) -> u32 {
        self.record.sequence
    }
    /// True for records that only appear inside another record (e.g. packets of a transaction).
    #[getter]
    fn nested(&self) -> bool {
        self.record.nested
    }
    #[getter]
    fn reserved(&self) -> u32 {
        self.record.reserved
    }
    /// 1-based id of the capture this record belongs to.
    #[getter]
    fn capture(&self) -> u8 {
        self.record.capture
    }
    #[getter]
    fn capture_flags(&self) -> u8 {
        self.record.capture_flags
    }
    /// Start time in analyzer ticks since the start of the capture.
    #[getter]
    fn timestamp(&self) -> u64 {
        self.record.timestamp
    }
    /// Duration in analyzer ticks.
    #[getter]
    fn duration(&self) -> u32 {
        self.record.duration
    }
    /// Start time in nanoseconds since the start of the capture.
    #[getter]
    fn time_ns(&self) -> Option<u128> {
        self.capture
            .as_ref()
            .map(|c| c.ticks_to_duration(self.record.timestamp).as_nanos())
    }
    /// Start time in nanoseconds since the Unix epoch.
    #[getter]
    fn absolute_time_ns(&self) -> Option<u128> {
        self.capture
            .as_ref()
            .map(|c| c.absolute_time(self.record.timestamp).as_nanos())
    }
    /// Duration in nanoseconds.
    #[getter]
    fn duration_ns(&self) -> Option<u128> {
        self.capture
            .as_ref()
            .map(|c| c.ticks_to_duration(self.record.duration as u64).as_nanos())
    }
    /// Every element of the record, as dicts with a `type` and a `tag` key.
    #[getter]
    fn elements<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        self.record
            .elements
            .iter()
            .map(|e| element_to_dict(py, e))
            .collect()
    }
    /// Raw USB packet bytes (PID, payload, CRC) if the record is a single packet.
    #[getter]
    fn packet_data<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.record.packet_data().map(|d| PyBytes::new(py, d))
    }
    /// "LS", "FS", "HS", or None when the record has no speed.
    #[getter]
    fn speed(&self) -> Option<String> {
        self.record.status().and_then(|s| speed_name(s.speed))
    }
    #[getter]
    fn error(&self) -> bool {
        self.record.status().is_some_and(|s| s.error)
    }
    #[getter]
    fn device_index(&self) -> Option<u16> {
        self.record.status().and_then(|s| s.device_index)
    }
    #[getter]
    fn pid(&self) -> Option<u8> {
        self.record.packet_info().map(|p| p.pid)
    }
    #[getter]
    fn address(&self) -> Option<u8> {
        self.record.packet_info().map(|p| p.address)
    }
    #[getter]
    fn endpoint(&self) -> Option<u8> {
        self.record.packet_info().map(|p| p.endpoint)
    }
    #[getter]
    fn direction_in(&self) -> Option<bool> {
        self.record.packet_info().map(|p| p.direction_in)
    }
    /// The user comment attached to this record, if any.
    #[getter]
    fn comment(&self) -> Option<String> {
        self.record.elements.iter().find_map(|e| match e {
            Element::Comment(text) => Some(text.clone()),
            _ => None,
        })
    }
    /// Code of the bus event (1 target disconnected, 4 reset, 7 host disconnected, 8 host
    /// connected, 0x0B speed detected, 0x0E suspend), if this record is one.
    #[getter]
    fn bus_event(&self) -> Option<u16> {
        self.record.elements.iter().find_map(|e| match e {
            Element::BusEvent { code, .. } => Some(*code),
            _ => None,
        })
    }
    /// Sequence numbers of the records this one groups (a transaction's packets, ...).
    #[getter]
    fn children(&self) -> Vec<u32> {
        self.record
            .elements
            .iter()
            .flat_map(|e| match e {
                Element::Transaction { children, .. } | Element::ChildList { children, .. } => {
                    children.as_slice()
                }
                _ => &[],
            })
            .copied()
            .collect()
    }

    fn __repr__(&self) -> String {
        let tags: Vec<String> = self
            .record
            .elements
            .iter()
            .map(|e| format!("{:#04x}", e.tag()))
            .collect();
        format!(
            "Record(sequence={}, capture={}, timestamp={}, elements=[{}])",
            self.record.sequence,
            self.record.capture,
            self.record.timestamp,
            tags.join(", ")
        )
    }
}

/// A Total Phase Data Center capture (.tdc), fully decompressed in memory.
#[pyclass(name = "TdcFile", module = "demuxusb", frozen)]
struct PyTdcFile {
    inner: tdc::TdcFile,
}

impl PyTdcFile {
    fn wrap(&self, record: Record) -> PyRecord {
        let capture = self.inner.capture(record.capture).cloned();
        PyRecord { record, capture }
    }
}

#[pymethods]
impl PyTdcFile {
    /// Opens and decodes a .tdc file.
    #[new]
    fn new(py: Python<'_>, path: PathBuf) -> PyResult<Self> {
        let inner = py.detach(|| tdc::TdcFile::open(path)).map_err(to_py_err)?;
        Ok(PyTdcFile { inner })
    }

    /// Same as `TdcFile(path)`.
    #[staticmethod]
    fn open(py: Python<'_>, path: PathBuf) -> PyResult<Self> {
        Self::new(py, path)
    }

    /// Decodes a .tdc file already in memory.
    #[staticmethod]
    fn parse(py: Python<'_>, data: &[u8]) -> PyResult<Self> {
        let inner = py.detach(|| tdc::TdcFile::parse(data)).map_err(to_py_err)?;
        Ok(PyTdcFile { inner })
    }

    #[getter]
    fn header(&self, py: Python<'_>) -> PyHeader {
        let h = &self.inner.header;
        PyHeader {
            signature_version: (h.signature_version[0], h.signature_version[1]),
            header_len: h.header_len,
            writer_version: (h.writer_version[0], h.writer_version[1]),
            saved_at: h.saved_at,
            format_version: h.format_version,
            element_types: h
                .element_types
                .iter()
                .map(|e| (e.version, e.tag, e.kind))
                .collect(),
            raw: PyBytes::new(py, &h.raw).unbind(),
        }
    }

    #[getter]
    fn captures(&self) -> Vec<PyCapture> {
        self.inner.captures.iter().map(PyCapture::from).collect()
    }

    #[getter]
    fn footer(&self, py: Python<'_>) -> Option<PyFooter> {
        self.inner.footer.as_ref().map(|f| PyFooter {
            version: f.version,
            data: PyBytes::new(py, &f.data).unbind(),
        })
    }

    /// FastLZ level of each compressed block.
    #[getter]
    fn block_levels(&self) -> Vec<u32> {
        self.inner.block_levels.iter().map(|&l| l as u32).collect()
    }

    /// The decompressed stream (capture table, records and footer).
    fn stream<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.stream())
    }

    fn capture(&self, id: u8) -> Option<PyCapture> {
        self.inner.capture(id).map(PyCapture::from)
    }

    /// The capture Data Center shows when the file is opened.
    fn last_capture(&self) -> Option<PyCapture> {
        self.inner.last_capture().map(PyCapture::from)
    }

    /// Iterates over every record, lazily. Decoding errors are raised as `TdcFormatError`.
    fn records(slf: Py<Self>) -> RecordIter {
        RecordIter {
            file: slf,
            offset: 0,
        }
    }

    fn __iter__(slf: Py<Self>) -> RecordIter {
        Self::records(slf)
    }

    /// Every packet record (optionally only of one capture), as a list.
    #[pyo3(signature = (capture=None))]
    fn packets(&self, capture: Option<u8>) -> PyResult<Vec<PyRecord>> {
        let mut out = Vec::new();
        for record in self.inner.records() {
            let record = record.map_err(to_py_err)?;
            if record.packet_data().is_none() || capture.is_some_and(|c| c != record.capture) {
                continue;
            }
            out.push(self.wrap(record));
        }
        Ok(out)
    }

    /// Writes the USB packets to a pcapng file Wireshark's `usbll` dissector understands.
    /// Returns the number of packets written.
    #[pyo3(signature = (path, capture=None))]
    fn write_pcapng(&self, py: Python<'_>, path: PathBuf, capture: Option<u8>) -> PyResult<usize> {
        py.detach(|| {
            let file = std::fs::File::create(path)?;
            tdc::pcap::write_pcapng(&self.inner, capture, std::io::BufWriter::new(file))
        })
        .map_err(to_py_err)
    }

    /// The pcapng export as bytes.
    #[pyo3(signature = (capture=None))]
    fn to_pcapng<'py>(
        &self,
        py: Python<'py>,
        capture: Option<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut out = Vec::new();
        py.detach(|| tdc::pcap::write_pcapng(&self.inner, capture, &mut out))
            .map_err(to_py_err)?;
        Ok(PyBytes::new(py, &out))
    }

    fn __repr__(&self) -> String {
        format!(
            "TdcFile(format_version={:#x}, captures={}, blocks={})",
            self.inner.header.format_version,
            self.inner.captures.len(),
            self.inner.block_levels.len()
        )
    }
}

#[pyclass(name = "RecordIterator", module = "demuxusb")]
struct RecordIter {
    file: Py<PyTdcFile>,
    offset: usize,
}

#[pymethods]
impl RecordIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> PyResult<Option<PyRecord>> {
        let file = self.file.get();
        let mut records = file.inner.records_at(self.offset);
        let next = records.next();
        self.offset = records.offset();
        match next {
            None => Ok(None),
            Some(Ok(record)) => Ok(Some(file.wrap(record))),
            Some(Err(err)) => Err(to_py_err(err)),
        }
    }
}

/// Readers for Total Phase USB analyzer captures.
#[pymodule]
#[pyo3(name = "demuxusb")]
fn demuxusb_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTdcFile>()?;
    m.add_class::<PyHeader>()?;
    m.add_class::<PyCapture>()?;
    m.add_class::<PyFooter>()?;
    m.add_class::<PyRecord>()?;
    m.add_class::<RecordIter>()?;
    m.add("TdcFormatError", m.py().get_type::<TdcFormatError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
