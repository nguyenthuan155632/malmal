# malmal-rails

Rails integration of the [malmal](https://github.com/nguyenthuan155632/malmal) upload
scanner: an Active Storage validator, a scan of every stored blob, attachments rebuilt
from what they draw, and one scanner for the application built from `config.malmal`.
Rails 7.1 to 8.1, Ruby 3.2 or newer. The scanner itself is the
[malmal](../malmal/README.md) gem, whose platform gems carry the library: no Rust needed.

```bash
bundle add malmal-rails
bin/rails generate malmal:install     # writes config/initializers/malmal.rb
```

## Refusing an upload

```ruby
class Document < ApplicationRecord
  has_one_attached :file
  has_many_attached :pages
  validates :file, malmal: true
  validates :pages, malmal: { policy: :documents, types: %i[pdf] }
end
```

The validator scans what is being attached, before it is uploaded: a file from a form,
an `{io:, filename:}` hash, or a blob already stored (a direct upload, a signed id),
which is read back up to the size limit. It uses the file name and the `Content-Type`
the client gave. Attachments the record already has are not scanned again; every file of
a `has_many_attached` is.

A file that is not clean adds `:malmal_suspicious` or `:malmal_malicious` to the
attribute, and one that could not be scanned `:malmal_error`. The details carry the
finding codes and the file name:

```ruby
document.errors.details[:file]
# => [{error: :malmal_malicious, filename: "photo.jpg", codes: ["type.executable"], count: 1}]
document.errors.full_messages
# => ["File could not be accepted: photo.jpg looks malicious"]
```

The messages are under `errors.messages.malmal_*` in `config/locales/en.yml`, to
override or translate. The validator takes the scanning options (`policy`, `allow`,
`types`, `max_memory`, `wait`, `pdf_passwords`), and `message:`; each set is built once
into a scanner of its own. An unknown option raises when the model is loaded.

## Rebuilding an attachment

```ruby
class User < ApplicationRecord
  has_one_attached :avatar
  sanitizes_attachment :avatar, types: %i[jpeg png webp]
end
```

Before validation, the upload is replaced with a file written anew from its pixels, so
nothing else from it is stored. The new file keeps the name of the upload, with the
extension of its type, which is not always the type of the upload (a BMP becomes a PNG).
A file that is not clean is refused as the validator does; one that cannot be rebuilt
adds `:malmal_not_rebuilt`, or is kept as it was with `on_not_rebuilt: :keep`, which is
best paired with the validator. The options are those of `Malmal::Scanner#sanitize`:
`types`, `jpeg_quality`, `keep_cmyk`, `pdf_dpi`, `pdf_jpeg`, `pdf_text`, `pdf_vector_text`.

## Stored blobs

Direct uploads reach the storage service before any validation runs. With
`config.malmal.scan_blobs` (on by default), every blob is scanned when Active Storage
analyzes it, in the analyze job, and the result is kept in its metadata:

```ruby
blob.metadata["malmal"]  # => {"verdict" => "malicious", "codes" => ["type.executable"]}
blob.malmal_clean?       # => false; nil before the scan
```

With `config.malmal.purge_unclean`, a blob that is not clean is purged, with its
attachments.

## Configuration

```ruby
# config/initializers/malmal.rb
Rails.application.configure do
  config.malmal.policy = :documents            # :default, :strict, :documents
  config.malmal.allow = %w[pdf.xfa]
  config.malmal.types = %i[jpeg png gif webp pdf]
  config.malmal.limits = { max_size: 20.megabytes, scan_timeout: 10 }
  config.malmal.max_memory = 256.megabytes
  config.malmal.wait = 30
  config.malmal.pdf_passwords = []
  config.malmal.scan_blobs = true
  config.malmal.purge_unclean = false
  config.malmal.log_filenames = false
end
```

`Malmal::Rails.scanner` is built from it on first use and shared by every thread. To
scan with a running `malmald` instead, which gives the sandbox and `--hard-timeout`:

```ruby
config.malmal.client_url = "http://127.0.0.1:8080"
config.malmal.client_token = ENV["MALMAL_TOKEN"]
```

The scanning options are then the daemon's flags, and a validator that sets its own
raises `ArgumentError`.

## Instrumentation

Each scan is an `ActiveSupport::Notifications` event `scan.malmal`, and each rebuild
`sanitize.malmal`; the payload has `filename`, `content_type`, and `report` or
`sanitized`. A scan that is not clean is logged as a warning, with its codes, and with
the file name only when `config.malmal.log_filenames` is on.

```ruby
ActiveSupport::Notifications.subscribe("scan.malmal") do |event|
  StatsD.increment("uploads.#{event.payload[:report].verdict}")
end
```

`Malmal::Rails.scan(io, filename:)` and `Malmal::Rails.sanitize` scan outside a model
with the same scanner and events.

## Development

```bash
cargo build --release -p malmal-ffi
cd bindings/ruby/malmal-rails
bundle install
MALMAL_LIBRARY=../../../target/release/libmalmal_ffi.so bundle exec rake test
BUNDLE_GEMFILE=gemfiles/rails_7_1.gemfile bundle install   # another Rails
```

[examples/rails](../../../examples/rails) is an application that uses all of it.

## License

MIT or Apache-2.0, at your option.
