# frozen_string_literal: true

require_relative "demuxusb/version"

begin
  # Precompiled gems put the extension in a per-Ruby-version directory.
  RUBY_VERSION =~ /(\d+\.\d+)/
  require_relative "demuxusb/#{Regexp.last_match(1)}/demuxusb"
rescue LoadError
  require_relative "demuxusb/demuxusb"
end

# Readers for Total Phase USB analyzer captures.
#
#   tdc = Demuxusb::TdcFile.open("capture.tdc")
#   tdc.each_record do |record|
#     puts "#{record.time_ns} #{record.speed} #{record.packet_data.unpack1('H*')}" if record.packet?
#   end
#   tdc.write_pcapng("capture.pcapng")
module Demuxusb
  # A Total Phase Data Center capture (.tdc), fully decompressed in memory.
  class TdcFile
    include Enumerable

    # Yields every record, decoding them lazily. Returns an Enumerator without a block.
    def each_record
      return enum_for(:each_record) unless block_given?

      offset = 0
      while (pair = _next_record(offset))
        record, offset = pair
        yield record
      end
      self
    end
    alias each each_record

    def records
      each_record
    end

    # Every record that holds a USB packet, optionally only those of one capture.
    def packets(capture: nil)
      _packets(capture)
    end

    # Writes the USB packets to a pcapng file Wireshark's usbll dissector understands.
    # Returns the number of packets written.
    def write_pcapng(path, capture: nil)
      _write_pcapng(path.to_s, capture)
    end

    # The pcapng export as a binary String.
    def to_pcapng(capture: nil)
      _to_pcapng(capture)
    end
  end
end
