# malmal for Ruby

The [malmal](https://github.com/nguyenthuan155632/malmal) upload scanner for any Ruby
program. It calls `libmalmal_ffi` through the `ffi` gem, and the platform gems carry
that library, so installing it needs no Rust. For Rails, see
[malmal-rails](../malmal-rails/README.md).

```ruby
require "malmal"

SCANNER = Malmal::Scanner.new          # build once, share between threads
report = SCANNER.scan(upload, filename: "a.png", content_type: "image/png")
reject(report.codes) unless report.clean?
```

Anything but `clean?`, including a `Malmal::ScanError`, means the file is not accepted.
A scan releases the GVL, so the other threads of a Puma worker carry on while it runs.

## Installing

```bash
bundle add malmal
```

RubyGems picks the gem for the machine:

| Platform | For |
|---|---|
| `x86_64-linux-gnu`, `aarch64-linux-gnu` | Linux with glibc 2.17 or newer (Debian, Ubuntu, RHEL) |
| `x86_64-linux-musl`, `aarch64-linux-musl` | Alpine |
| `arm64-darwin`, `x86_64-darwin` | macOS |
| `ruby` | anything else, with a library of your own at `MALMAL_LIBRARY` |

The gem loads the library at `MALMAL_LIBRARY` if that is set, else the one it carries,
else `libmalmal_ffi` from the system's library path. It has to be of the gem's version,
except at `MALMAL_LIBRARY`; otherwise `Malmal::LoadError` says what was found. A library
for the `ruby` gem is built from a checkout of malmal with:

```bash
cargo build --release -p malmal-ffi
export MALMAL_LIBRARY=$PWD/target/release/libmalmal_ffi.so
```

Ruby 3.2 or newer.

## Scanning

```ruby
scanner = Malmal::Scanner.new(
  policy: :documents,                 # or :default, :strict
  allow: %w[pdf.xfa],                 # codes that do not count against a file
  types: %i[jpeg png pdf],            # accepted file types; every supported one if nil
  hashlist: File.read("blocklist.txt"),
  pdf_passwords: ["statement-password"],
  max_size: 20 << 20, scan_timeout: 5, # also max_decompressed, max_pixels, max_depth
  max_memory: 256 << 20,              # what one scan may hold; 512 MiB if not given
  wait: 30                            # answer within 30 s whatever the file does
)
```

An unknown option, policy, type or code raises `ArgumentError`. With `wait`, a scan that
has not ended in time is reported with `limit.time`, never clean, and left running on
its thread; `scanner.overdue` counts those, and above 0 the process is due a restart.

`scan` takes a String or an IO. An IO is read up to `max_size` and one byte past it, so
that a file too large is reported as such. The `Malmal::Report` it returns has `verdict`
(`:clean`, `:suspicious` or `:malicious`), `clean?`, `suspicious?`, `malicious?`,
`detected_type`, `declared_types`, `size`, `sha256`, `findings`, `codes` and `to_h`.
Each `Malmal::Finding` has `code`, `severity` (`:info` to `:critical`), `message` and
`offset`.

## Rebuilding files

`sanitize` scans and then writes a clean file anew from what it draws, so that nothing
else is kept:

```ruby
begin
  image = scanner.sanitize(upload, filename: "a.png", jpeg_quality: 85)
rescue Malmal::Rejected => e       # the scan did not come back clean
  reject(e.report.codes)
rescue Malmal::NotRebuilt          # clean, but not a file that can be rebuilt
  reject
else
  store(image.data, image.content_type, "a#{image.extension}")
end
```

The type can change: a BMP, TIFF or ICO comes out as a PNG. `Malmal::Sanitized` has
`data`, `file_type`, `content_type`, `extension`, `width`, `height`, `frames` and
`report`. `sanitize` also takes `types`, `pdf_dpi`, `pdf_jpeg`, `pdf_text` and
`pdf_vector_text`; PDFs are rebuilt only by a library built with `cdr-pdf`. Both
exceptions are a `Malmal::SanitizeError`.

## Speed

A scan from Ruby costs 10 to 16 µs more than the same scan from Rust: the copy of the
data, the report as JSON, and releasing the GVL. From some 20 KB up, the difference is
within 5%. `ruby -Ilib bench/throughput.rb FILE...` measures it on your files.

## With malmald

`Malmal::Client` answers as `Scanner` does, from a running `malmald`. It is for
deployments that want what only the daemon gives: the sandbox, and `--hard-timeout`
ending a scan that does not end.

```ruby
client = Malmal::Client.new("http://127.0.0.1:8080", token: ENV["MALMAL_TOKEN"])
client.scan(upload, filename: "a.png").clean?
client.healthy?
```

The scanning options are then the daemon's flags. `sanitize` takes `types` only, checked
against the type of the rebuilt file. A daemon that cannot be reached, or does not answer
with a report, raises `Malmal::ScanError`.

## Development

```bash
cargo build --release -p malmal-ffi
cd bindings/ruby/malmal
bundle install
MALMAL_LIBRARY=../../../target/release/libmalmal_ffi.so bundle exec rake test
```

With `MALMALD` set to a `malmald` binary, the client tests run against it too.
`bindings/ruby/build_gem.sh <rust-target>` builds a platform gem into `bindings/ruby/pkg`.

## License

MIT or Apache-2.0, at your option.
