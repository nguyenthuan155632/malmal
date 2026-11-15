# A Rails app with malmal

A small Rails 8.1 application that takes uploads through
[malmal-rails](../../bindings/ruby/malmal-rails/README.md):

- a document (`Document#file`) is kept as it was uploaded, once the validator finds it
  clean, under the `documents` policy;
- an avatar (`Profile#avatar`) is rebuilt with `sanitizes_attachment`, and only the new
  file is stored;
- every stored blob is scanned again when Active Storage analyzes it, and purged if it is
  not clean.

The parts to read are [config/initializers/malmal.rb](config/initializers/malmal.rb),
[app/models](app/models) and
[app/controllers/uploads_controller.rb](app/controllers/uploads_controller.rb).

## Running it

With Ruby 3.2 or newer:

```bash
cd examples/rails
bundle install
bin/rails db:prepare
bin/rails server
```

Then open http://127.0.0.1:3000. Try a clean file, and one from
[tests/corpus/malicious](../../tests/corpus/malicious): `password-javascript.pdf` as a
document is refused with `pdf.javascript`, and
[tests/corpus/clean/pixels-spell-pdf.png](../../tests/corpus/clean/pixels-spell-pdf.png)
as an avatar is refused with `image.polyglot`. The page lists what was stored, with the
verdict the blob scan recorded.

To use the gems of this checkout rather than the released ones, with a library built
from it:

```bash
cargo build --release -p malmal-ffi
MALMAL_FROM_CHECKOUT=1 MALMAL_LIBRARY=$PWD/../../target/release/libmalmal_ffi.so bin/rails server
```

## Beside malmald

[compose.yaml](compose.yaml) runs the app with `malmald` next to it. The app then scans
over HTTP with a token, and the scanning options are the daemon's flags:

```bash
head -c 32 /dev/urandom | base64 > token
docker compose up --build
```

The same works without containers: start `malmald --http 127.0.0.1:8080 --token-file
token --policy documents`, then run the app with `MALMAL_URL=http://127.0.0.1:8080` and
`MALMAL_TOKEN_FILE=token`.

## Checking it

`bin/try` starts the app on port 3999, uploads five files from the corpus through its
forms, and checks each answer:

```bash
MALMAL_FROM_CHECKOUT=1 MALMAL_LIBRARY=$PWD/../../target/release/libmalmal_ffi.so bin/try
```

```
ok    page.pdf: page.pdf was accepted.
ok    invoice.pdf: File could not be accepted: invoice.pdf looks malicious (type.mismatch, type.executable)
ok    locked.pdf: File could not be accepted: locked.pdf looks malicious (pdf.open_action, pdf.javascript, pdf.encrypted)
ok    me.jpg: The avatar was rebuilt as me.jpg.
ok    me.png: Avatar could not be accepted: me.png looks malicious (image.polyglot)
```

It exits non-zero, with the end of the server log, when an answer is not the expected
one. With `MALMAL_URL` set, it checks the client mode.
