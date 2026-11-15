# frozen_string_literal: true

# Measure scan throughput from Ruby, as crates/malmal/examples/throughput.rs
# does from Rust, so that the two show what the copy over FFI and the JSON
# report cost:
#
#   ruby -Ilib bench/throughput.rb FILE...
#
# Each file is read once and scanned repeatedly in memory.

require "malmal"

MIN_RUN = 0.3

scanner = Malmal::Scanner.new
puts "     size   ms/scan       MB/s  type        file"
ARGV.each do |path|
  data = File.binread(path)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  runs = 0
  detected = nil
  while runs.zero? || Process.clock_gettime(Process::CLOCK_MONOTONIC) - started < MIN_RUN
    detected = scanner.scan(data, filename: path).detected_type
    runs += 1
  end
  per_scan = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) / runs
  puts format("%<size>9d %<ms>9.3f %<rate>10.1f  %<type>-10s  %<path>s",
              size: data.bytesize, ms: per_scan * 1000, rate: data.bytesize / per_scan / 1e6,
              type: detected, path: path)
end
