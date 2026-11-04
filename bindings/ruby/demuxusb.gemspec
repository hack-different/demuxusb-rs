# frozen_string_literal: true

require_relative "lib/demuxusb/version"

Gem::Specification.new do |spec|
  spec.name = "demuxusb"
  spec.version = Demuxusb::VERSION
  spec.authors = ["hack-different"]
  spec.summary = "Readers for Total Phase USB analyzer captures (Data Center .tdc files)"
  spec.homepage = "https://github.com/hack-different/demuxusb-rs"
  spec.licenses = ["MIT", "Apache-2.0"]
  spec.metadata = { "source_code_uri" => spec.homepage }
  spec.required_ruby_version = ">= 3.0"

  spec.files = Dir["lib/**/*.rb", "ext/**/*.{rs,rb,toml}", "demuxusb.gemspec", "LICENSE-*"]
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/demuxusb/extconf.rb"]

  spec.add_dependency "rb_sys", "~> 0.9"
end
