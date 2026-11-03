# frozen_string_literal: true

require_relative "lib/demuxusb/version"

Gem::Specification.new do |spec|
  spec.name = "demuxusb"
  spec.version = Demuxusb::VERSION
  spec.authors = ["hack-different"]
  spec.summary = "Readers for Total Phase USB analyzer captures (Data Center .tdc files)"
  spec.homepage = "https://github.com/hack-different/demuxusb-rs"
  spec.required_ruby_version = ">= 3.0"

  spec.files = Dir["lib/**/*.rb", "ext/**/*.{rs,rb,toml}", "demuxusb.gemspec"]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/demuxusb/extconf.rb"]

  spec.add_dependency "rb_sys", "~> 0.9"
end
