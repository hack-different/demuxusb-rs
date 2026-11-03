# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "demuxusb"

class TestTdc < Minitest::Test
  REPO = File.expand_path("../../..", __dir__)
  TESTDATA = ENV.fetch("DEMUXUSB_TESTDATA", File.join(REPO, "ext", "testdata"))
  FT230X = File.join(TESTDATA, "serial", "ftdi", "FT230X_Basic_UART_w7_init.tdc")
  BLOCK_SIZE = 1 << 20

  # Wraps an uncompressed stream in a .tdc container using literal-only FastLZ blocks.
  def build_file(stream)
    header = ("\0" * 0x1a8).b
    header[0, 4] = "TPDC"
    header[4, 2] = "\x00\x03".b
    header[6, 2] = [0x1a8].pack("v")
    header[0x14, 2] = [0x10a].pack("v")
    header[0x26, 2] = [2].pack("v")
    header[0x28, 8] = [3, 0, 0, 0, 1, 0, 0x0b, 3].pack("C*")
    out = header.dup
    (0...stream.bytesize).step(BLOCK_SIZE) do |start|
      block = stream.byteslice(start, BLOCK_SIZE)
      compressed = "".b
      (0...block.bytesize).step(32) do |i|
        literal = block.byteslice(i, 32)
        compressed << (literal.bytesize - 1).chr << literal
      end
      out << "\0" << [compressed.bytesize].pack("V")[0, 3] << ("\0" * 4) << compressed
    end
    out
  end

  def capture_entry(id)
    [0x05].pack("C") + [id, 3, 1_414_535_317, 1_414_535_400].pack("V4") +
      [120_000_000].pack("Q<") + [60_000_000].pack("V") + ("\0" * 16).b
  end

  def packet_record(sequence, timestamp, data)
    elements = [0x00, 3, 10, 0, 0, 0, 0x03, 0, 0xff, 0xff].pack("C*")
    elements += [0x0b, 3].pack("C*") + [14 + data.bytesize, 0, data.bytesize].pack("V3") + data
    record = [0x10].pack("C") + [30 + elements.bytesize].pack("v") + "\0".b
    record += [sequence, 0, 20].pack("V3") + [1, 0].pack("C*")
    record + [timestamp].pack("Q<") + [45].pack("V") + elements
  end

  def synthetic(count = 10)
    stream = capture_entry(1)
    count.times { |i| stream += packet_record(i, i * 60, [0x69, i & 0x7f, 0x10].pack("C*")) }
    stream += [0x06, 3, 0, 0, 0, 2, 0, 0, 0, 0xaa, 0xbb].pack("C*")
    build_file(stream)
  end

  def test_parses_synthetic_file
    tdc = Demuxusb::TdcFile.parse(synthetic)
    assert_equal 0x10a, tdc.header[:format_version]
    assert_equal [[3, 0, 0], [1, 11, 3]], tdc.header[:element_types]
    assert_equal 1, tdc.captures.size
    assert_equal 60_000_000, tdc.last_capture.ticks_per_second
    assert_equal({ version: 3, data: "\xaa\xbb".b }, tdc.footer)

    records = tdc.to_a
    assert_equal (0...10).to_a, records.map(&:sequence)
    r = records[3]
    assert r.packet?
    assert_equal "\x69\x03\x10".b, r.packet_data
    assert_equal Encoding::BINARY, r.packet_data.encoding
    assert_equal 180, r.timestamp
    assert_equal 3_000, r.time_ns
    assert_equal 1_414_535_317 * 10**9 + 3_000, r.absolute_time_ns
    assert_equal 750, r.duration_ns
    assert_equal "FS", r.speed
    assert_nil r.pid
    assert_equal %i[status packet], r.elements.map { |e| e[:type] }
    assert_equal({ status: 0, data: "\x69\x03\x10".b, tag: 0x0b, type: :packet }, r.elements[1])
  end

  def test_each_record_is_lazy
    tdc = Demuxusb::TdcFile.parse(synthetic(5))
    enum = tdc.each_record
    assert_equal 0, enum.next.sequence
    assert_equal 1, enum.next.sequence
    assert_equal 5, tdc.count
    assert_equal [3, 4], tdc.lazy.select { |r| r.sequence > 2 }.map(&:sequence).to_a
  end

  def test_pcapng_export
    tdc = Demuxusb::TdcFile.parse(synthetic(4))
    Dir.mktmpdir do |dir|
      out = File.join(dir, "out.pcapng")
      assert_equal 4, tdc.write_pcapng(out)
      assert_equal File.binread(out), tdc.to_pcapng
      assert_equal 0, tdc.write_pcapng(out, capture: 2)
    end
    assert_equal "\x0a\x0d\x0d\x0a".b, tdc.to_pcapng.byteslice(0, 4)
  end

  def test_errors
    err = assert_raises(Demuxusb::FormatError) { Demuxusb::TdcFile.parse("XXXX" + ("\0" * 100)) }
    assert_match(/not a Data Center file/, err.message)
    assert_raises(Demuxusb::Error) { Demuxusb::TdcFile.parse("TPDC") }
    assert_raises(IOError) { Demuxusb::TdcFile.open("/does/not/exist.tdc") }
  end

  def test_real_capture
    skip "USBTraces testdata not checked out" unless File.exist?(FT230X)
    tdc = Demuxusb::TdcFile.open(FT230X)
    assert_equal [1, 2], tdc.captures.map(&:id)
    packets = tdc.packets
    assert_equal tdc.count(&:packet?), packets.size
    assert_equal packets.size, tdc.write_pcapng(File::NULL)
    assert(packets.all? { |p| p.speed == "FS" })
  end
end
