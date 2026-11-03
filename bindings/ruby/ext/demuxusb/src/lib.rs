//! Ruby bindings for the Total Phase readers in `demuxusb-rs`.
//!
//! The native part lives under `Demuxusb`; `lib/demuxusb.rb` adds `TdcFile#each_record` on top
//! of `TdcFile#_next_record` so iteration stays lazy without holding a Rust borrow across Ruby.

use demuxusb_rs::tdc::{self, Element, Record, Speed, TdcError};
use magnus::{
    function, method, prelude::*, Error, ExceptionClass, IntoValue, RArray, RHash, RModule,
    RString, Ruby, Value,
};

fn format_error(ruby: &Ruby) -> ExceptionClass {
    ruby.class_object()
        .const_get::<_, RModule>("Demuxusb")
        .and_then(|m| m.const_get("FormatError"))
        .unwrap_or_else(|_| ruby.exception_runtime_error())
}

fn to_rb_err(ruby: &Ruby, err: TdcError) -> Error {
    match err {
        TdcError::Io(io) => Error::new(ruby.exception_io_error(), io.to_string()),
        other => Error::new(format_error(ruby), other.to_string()),
    }
}

fn speed_name(speed: Speed) -> Option<String> {
    match speed {
        Speed::Unknown => None,
        other => Some(other.to_string()),
    }
}

fn bytes(ruby: &Ruby, data: &[u8]) -> RString {
    ruby.str_from_slice(data)
}

fn ns(duration: std::time::Duration) -> u64 {
    duration.as_nanos() as u64
}

/// One capture session. Records refer to it by `Record#capture`.
#[magnus::wrap(class = "Demuxusb::Capture", free_immediately, size)]
struct RbCapture(tdc::Capture);

impl RbCapture {
    fn id(&self) -> u32 {
        self.0.id
    }
    fn kind(&self) -> u32 {
        self.0.kind
    }
    fn started_at(&self) -> u32 {
        self.0.started_at
    }
    fn stopped_at(&self) -> u32 {
        self.0.stopped_at
    }
    fn duration_ticks(&self) -> u64 {
        self.0.duration_ticks
    }
    fn ticks_per_second(&self) -> u32 {
        self.0.ticks_per_second
    }
    fn extra(ruby: &Ruby, rb_self: &Self) -> RString {
        bytes(ruby, &rb_self.0.extra)
    }
    fn duration_ns(&self) -> u64 {
        ns(self.0.ticks_to_duration(self.0.duration_ticks))
    }
    fn ticks_to_ns(&self, ticks: u64) -> u64 {
        ns(self.0.ticks_to_duration(ticks))
    }
    fn absolute_time_ns(&self, ticks: u64) -> u64 {
        ns(self.0.absolute_time(ticks))
    }
    fn inspect(&self) -> String {
        format!(
            "#<Demuxusb::Capture id={} started_at={} duration_ticks={}>",
            self.0.id, self.0.started_at, self.0.duration_ticks
        )
    }
}

fn element_to_hash(ruby: &Ruby, element: &Element) -> Result<RHash, Error> {
    let h = ruby.hash_new();
    let set = |key: &str, value: Value| h.aset(ruby.to_symbol(key), value);
    let kind = match element {
        Element::Status(s) => {
            set("raw", s.raw.into_value_with(ruby))?;
            set("speed", speed_name(s.speed).into_value_with(ruby))?;
            set("error", s.error.into_value_with(ruby))?;
            set("reserved", s.reserved.into_value_with(ruby))?;
            set("device_index", s.device_index.into_value_with(ruby))?;
            "status"
        }
        Element::CaptureStarted => "capture_started",
        Element::BusRecord => "bus_record",
        Element::PacketInfo(p) => {
            set("pid", p.pid.into_value_with(ruby))?;
            set("kind", p.kind.into_value_with(ruby))?;
            set("address", p.address.into_value_with(ruby))?;
            set("endpoint", p.endpoint.into_value_with(ruby))?;
            set("direction_in", p.direction_in.into_value_with(ruby))?;
            "packet_info"
        }
        Element::GroupInfo {
            raw,
            address,
            endpoint,
            direction_in,
        } => {
            set("raw", bytes(ruby, raw).as_value())?;
            set("address", address.into_value_with(ruby))?;
            set("endpoint", endpoint.into_value_with(ruby))?;
            set("direction_in", direction_in.into_value_with(ruby))?;
            "group_info"
        }
        Element::GroupCount { count, reserved } => {
            set("count", count.into_value_with(ruby))?;
            set("reserved", reserved.into_value_with(ruby))?;
            "group_count"
        }
        Element::SofGroup {
            count,
            reserved,
            flags,
            first_frame,
            last_frame,
        } => {
            set("count", count.into_value_with(ruby))?;
            set("reserved", reserved.into_value_with(ruby))?;
            set("flags", flags.into_value_with(ruby))?;
            set("first_frame", first_frame.into_value_with(ruby))?;
            set("last_frame", last_frame.into_value_with(ruby))?;
            "sof_group"
        }
        Element::Packet { status, data } => {
            set("status", status.into_value_with(ruby))?;
            set("data", bytes(ruby, data).as_value())?;
            "packet"
        }
        Element::Transaction { kind, children } => {
            set("kind", kind.into_value_with(ruby))?;
            set("children", ruby.ary_from_vec(children.clone()).as_value())?;
            "transaction"
        }
        Element::BusEvent {
            code,
            flags,
            reserved,
        } => {
            set("code", code.into_value_with(ruby))?;
            set("flags", flags.into_value_with(ruby))?;
            set("reserved", reserved.into_value_with(ruby))?;
            "bus_event"
        }
        Element::ChildList {
            count, children, ..
        } => {
            set("count", count.into_value_with(ruby))?;
            set("children", ruby.ary_from_vec(children.clone()).as_value())?;
            "child_list"
        }
        Element::Comment(text) => {
            set("text", ruby.str_new(text).as_value())?;
            "comment"
        }
        Element::Flag(_) => "flag",
        Element::Unknown { data, .. } => {
            set("data", bytes(ruby, data).as_value())?;
            "unknown"
        }
    };
    set("tag", element.tag().into_value_with(ruby))?;
    set("type", ruby.to_symbol(kind).as_value())?;
    Ok(h)
}

/// One record of the capture: a packet, a transaction, a bus event, a comment, ...
#[magnus::wrap(class = "Demuxusb::Record", free_immediately, size)]
struct RbRecord {
    record: Record,
    capture: Option<tdc::Capture>,
}

impl RbRecord {
    fn offset(&self) -> usize {
        self.record.offset
    }
    fn flags(&self) -> u8 {
        self.record.flags
    }
    fn sequence(&self) -> u32 {
        self.record.sequence
    }
    fn nested(&self) -> bool {
        self.record.nested
    }
    fn reserved(&self) -> u32 {
        self.record.reserved
    }
    fn capture(&self) -> u8 {
        self.record.capture
    }
    fn capture_flags(&self) -> u8 {
        self.record.capture_flags
    }
    fn timestamp(&self) -> u64 {
        self.record.timestamp
    }
    fn duration(&self) -> u32 {
        self.record.duration
    }
    fn time_ns(&self) -> Option<u64> {
        self.capture
            .as_ref()
            .map(|c| ns(c.ticks_to_duration(self.record.timestamp)))
    }
    fn absolute_time_ns(&self) -> Option<u64> {
        self.capture
            .as_ref()
            .map(|c| ns(c.absolute_time(self.record.timestamp)))
    }
    fn duration_ns(&self) -> Option<u64> {
        self.capture
            .as_ref()
            .map(|c| ns(c.ticks_to_duration(self.record.duration as u64)))
    }
    fn elements(ruby: &Ruby, rb_self: &Self) -> Result<RArray, Error> {
        let out = ruby.ary_new_capa(rb_self.record.elements.len());
        for element in &rb_self.record.elements {
            out.push(element_to_hash(ruby, element)?)?;
        }
        Ok(out)
    }
    fn packet_data(ruby: &Ruby, rb_self: &Self) -> Option<RString> {
        rb_self.record.packet_data().map(|d| bytes(ruby, d))
    }
    fn is_packet(&self) -> bool {
        self.record.packet_data().is_some()
    }
    fn speed(&self) -> Option<String> {
        self.record.status().and_then(|s| speed_name(s.speed))
    }
    fn error(&self) -> bool {
        self.record.status().is_some_and(|s| s.error)
    }
    fn device_index(&self) -> Option<u16> {
        self.record.status().and_then(|s| s.device_index)
    }
    fn pid(&self) -> Option<u8> {
        self.record.packet_info().map(|p| p.pid)
    }
    fn address(&self) -> Option<u8> {
        self.record.packet_info().map(|p| p.address)
    }
    fn endpoint(&self) -> Option<u8> {
        self.record.packet_info().map(|p| p.endpoint)
    }
    fn direction_in(&self) -> Option<bool> {
        self.record.packet_info().map(|p| p.direction_in)
    }
    fn comment(&self) -> Option<String> {
        self.record.elements.iter().find_map(|e| match e {
            Element::Comment(text) => Some(text.clone()),
            _ => None,
        })
    }
    fn bus_event(&self) -> Option<u16> {
        self.record.elements.iter().find_map(|e| match e {
            Element::BusEvent { code, .. } => Some(*code),
            _ => None,
        })
    }
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
    fn inspect(&self) -> String {
        let tags: Vec<String> = self
            .record
            .elements
            .iter()
            .map(|e| format!("{:#04x}", e.tag()))
            .collect();
        format!(
            "#<Demuxusb::Record sequence={} capture={} timestamp={} elements=[{}]>",
            self.record.sequence,
            self.record.capture,
            self.record.timestamp,
            tags.join(", ")
        )
    }
}

/// A Total Phase Data Center capture (.tdc), fully decompressed in memory.
#[magnus::wrap(class = "Demuxusb::TdcFile", free_immediately, size)]
struct RbTdcFile(tdc::TdcFile);

impl RbTdcFile {
    fn open(ruby: &Ruby, path: String) -> Result<Self, Error> {
        tdc::TdcFile::open(path)
            .map(RbTdcFile)
            .map_err(|e| to_rb_err(ruby, e))
    }

    fn parse(ruby: &Ruby, data: RString) -> Result<Self, Error> {
        // SAFETY: the slice is copied before any other Ruby code can run.
        let data = unsafe { data.as_slice().to_vec() };
        tdc::TdcFile::parse(&data)
            .map(RbTdcFile)
            .map_err(|e| to_rb_err(ruby, e))
    }

    fn wrap(&self, record: Record) -> RbRecord {
        let capture = self.0.capture(record.capture).cloned();
        RbRecord { record, capture }
    }

    fn header(ruby: &Ruby, rb_self: &Self) -> Result<RHash, Error> {
        let header = &rb_self.0.header;
        let h = ruby.hash_new();
        h.aset(
            ruby.to_symbol("signature_version"),
            bytes(ruby, &header.signature_version),
        )?;
        h.aset(ruby.to_symbol("header_len"), header.header_len)?;
        h.aset(
            ruby.to_symbol("writer_version"),
            ruby.ary_from_vec(header.writer_version.to_vec()),
        )?;
        h.aset(ruby.to_symbol("saved_at"), header.saved_at)?;
        h.aset(ruby.to_symbol("format_version"), header.format_version)?;
        let types = ruby.ary_new_capa(header.element_types.len());
        for t in &header.element_types {
            types.push((t.version, t.tag, t.kind))?;
        }
        h.aset(ruby.to_symbol("element_types"), types)?;
        h.aset(ruby.to_symbol("raw"), bytes(ruby, &header.raw))?;
        Ok(h)
    }

    fn captures(ruby: &Ruby, rb_self: &Self) -> Result<RArray, Error> {
        let out = ruby.ary_new_capa(rb_self.0.captures.len());
        for capture in &rb_self.0.captures {
            out.push(RbCapture(capture.clone()))?;
        }
        Ok(out)
    }

    fn capture(&self, id: u8) -> Option<RbCapture> {
        self.0.capture(id).cloned().map(RbCapture)
    }

    fn last_capture(&self) -> Option<RbCapture> {
        self.0.last_capture().cloned().map(RbCapture)
    }

    fn footer(ruby: &Ruby, rb_self: &Self) -> Result<Option<RHash>, Error> {
        let Some(footer) = &rb_self.0.footer else {
            return Ok(None);
        };
        let h = ruby.hash_new();
        h.aset(ruby.to_symbol("version"), footer.version)?;
        h.aset(ruby.to_symbol("data"), bytes(ruby, &footer.data))?;
        Ok(Some(h))
    }

    fn block_levels(&self) -> Vec<u8> {
        self.0.block_levels.clone()
    }

    fn stream(ruby: &Ruby, rb_self: &Self) -> RString {
        bytes(ruby, rb_self.0.stream())
    }

    /// Returns `[record, next_offset]`, or nil at the end. Offset 0 starts at the first record.
    fn next_record(
        ruby: &Ruby,
        rb_self: &Self,
        offset: usize,
    ) -> Result<Option<(RbRecord, usize)>, Error> {
        let mut records = rb_self.0.records_at(offset);
        match records.next() {
            None => Ok(None),
            Some(Ok(record)) => Ok(Some((rb_self.wrap(record), records.offset()))),
            Some(Err(err)) => Err(to_rb_err(ruby, err)),
        }
    }

    fn packets(ruby: &Ruby, rb_self: &Self, capture: Option<u8>) -> Result<RArray, Error> {
        let out = ruby.ary_new();
        for record in rb_self.0.records() {
            let record = record.map_err(|e| to_rb_err(ruby, e))?;
            if record.packet_data().is_none() || capture.is_some_and(|c| c != record.capture) {
                continue;
            }
            out.push(rb_self.wrap(record))?;
        }
        Ok(out)
    }

    fn write_pcapng(
        ruby: &Ruby,
        rb_self: &Self,
        path: String,
        capture: Option<u8>,
    ) -> Result<usize, Error> {
        std::fs::File::create(path)
            .map_err(TdcError::Io)
            .and_then(|file| {
                tdc::pcap::write_pcapng(&rb_self.0, capture, std::io::BufWriter::new(file))
            })
            .map_err(|e| to_rb_err(ruby, e))
    }

    fn to_pcapng(ruby: &Ruby, rb_self: &Self, capture: Option<u8>) -> Result<RString, Error> {
        let mut out = Vec::new();
        tdc::pcap::write_pcapng(&rb_self.0, capture, &mut out).map_err(|e| to_rb_err(ruby, e))?;
        Ok(bytes(ruby, &out))
    }

    fn inspect(&self) -> String {
        format!(
            "#<Demuxusb::TdcFile format_version={:#x} captures={} blocks={}>",
            self.0.header.format_version,
            self.0.captures.len(),
            self.0.block_levels.len()
        )
    }
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("Demuxusb")?;
    let error = module.define_error("Error", ruby.exception_standard_error())?;
    module.define_error("FormatError", error)?;

    let tdc_file = module.define_class("TdcFile", ruby.class_object())?;
    tdc_file.define_singleton_method("open", function!(RbTdcFile::open, 1))?;
    tdc_file.define_singleton_method("parse", function!(RbTdcFile::parse, 1))?;
    tdc_file.define_method("header", method!(RbTdcFile::header, 0))?;
    tdc_file.define_method("captures", method!(RbTdcFile::captures, 0))?;
    tdc_file.define_method("capture", method!(RbTdcFile::capture, 1))?;
    tdc_file.define_method("last_capture", method!(RbTdcFile::last_capture, 0))?;
    tdc_file.define_method("footer", method!(RbTdcFile::footer, 0))?;
    tdc_file.define_method("block_levels", method!(RbTdcFile::block_levels, 0))?;
    tdc_file.define_method("stream", method!(RbTdcFile::stream, 0))?;
    tdc_file.define_private_method("_next_record", method!(RbTdcFile::next_record, 1))?;
    tdc_file.define_private_method("_packets", method!(RbTdcFile::packets, 1))?;
    tdc_file.define_private_method("_write_pcapng", method!(RbTdcFile::write_pcapng, 2))?;
    tdc_file.define_private_method("_to_pcapng", method!(RbTdcFile::to_pcapng, 1))?;
    tdc_file.define_method("inspect", method!(RbTdcFile::inspect, 0))?;

    let capture = module.define_class("Capture", ruby.class_object())?;
    capture.define_method("id", method!(RbCapture::id, 0))?;
    capture.define_method("kind", method!(RbCapture::kind, 0))?;
    capture.define_method("started_at", method!(RbCapture::started_at, 0))?;
    capture.define_method("stopped_at", method!(RbCapture::stopped_at, 0))?;
    capture.define_method("duration_ticks", method!(RbCapture::duration_ticks, 0))?;
    capture.define_method("ticks_per_second", method!(RbCapture::ticks_per_second, 0))?;
    capture.define_method("extra", method!(RbCapture::extra, 0))?;
    capture.define_method("duration_ns", method!(RbCapture::duration_ns, 0))?;
    capture.define_method("ticks_to_ns", method!(RbCapture::ticks_to_ns, 1))?;
    capture.define_method("absolute_time_ns", method!(RbCapture::absolute_time_ns, 1))?;
    capture.define_method("inspect", method!(RbCapture::inspect, 0))?;

    let record = module.define_class("Record", ruby.class_object())?;
    record.define_method("offset", method!(RbRecord::offset, 0))?;
    record.define_method("flags", method!(RbRecord::flags, 0))?;
    record.define_method("sequence", method!(RbRecord::sequence, 0))?;
    record.define_method("nested?", method!(RbRecord::nested, 0))?;
    record.define_method("reserved", method!(RbRecord::reserved, 0))?;
    record.define_method("capture", method!(RbRecord::capture, 0))?;
    record.define_method("capture_flags", method!(RbRecord::capture_flags, 0))?;
    record.define_method("timestamp", method!(RbRecord::timestamp, 0))?;
    record.define_method("duration", method!(RbRecord::duration, 0))?;
    record.define_method("time_ns", method!(RbRecord::time_ns, 0))?;
    record.define_method("absolute_time_ns", method!(RbRecord::absolute_time_ns, 0))?;
    record.define_method("duration_ns", method!(RbRecord::duration_ns, 0))?;
    record.define_method("elements", method!(RbRecord::elements, 0))?;
    record.define_method("packet_data", method!(RbRecord::packet_data, 0))?;
    record.define_method("packet?", method!(RbRecord::is_packet, 0))?;
    record.define_method("speed", method!(RbRecord::speed, 0))?;
    record.define_method("error?", method!(RbRecord::error, 0))?;
    record.define_method("device_index", method!(RbRecord::device_index, 0))?;
    record.define_method("pid", method!(RbRecord::pid, 0))?;
    record.define_method("address", method!(RbRecord::address, 0))?;
    record.define_method("endpoint", method!(RbRecord::endpoint, 0))?;
    record.define_method("direction_in", method!(RbRecord::direction_in, 0))?;
    record.define_method("comment", method!(RbRecord::comment, 0))?;
    record.define_method("bus_event", method!(RbRecord::bus_event, 0))?;
    record.define_method("children", method!(RbRecord::children, 0))?;
    record.define_method("inspect", method!(RbRecord::inspect, 0))?;
    Ok(())
}
