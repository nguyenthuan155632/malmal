# malmal for Python

A thin wrapper over the C library of the [malmal](https://github.com/nguyenthuan155632/malmal)
upload scanner. It has no dependencies beyond the standard library.

```python
import malmal

scanner = malmal.Scanner()          # build once, share between threads
report = scanner.scan(data, filename="a.png", content_type="image/png")
if not report.clean:
    reject([finding["code"] for finding in report.findings])
```

Anything but `report.clean`, including a `malmal.ScanError`, means the file is not accepted.
`Scanner(pdf_passwords=["..."])` supplies passwords to try on encrypted PDFs, and
`Scanner(allow=["pdf.xfa", "pdf.embedded_file"])` names finding codes that do not count
against a file; they are still reported, at `"info"`. A code that does not exist raises
`ValueError`. Which codes honest files carry, and what letting each through takes on, is
in the [main README](https://github.com/nguyenthuan155632/malmal#allowing-finding-codes).
`Scanner(max_memory=...)` is what one scan may hold, in bytes (512 MiB unless given;
`None` or `0` for no limit); a scan that holds more is stopped with `limit.memory`.

```python
scanner = malmal.Scanner(
    policy="documents",                # or "default", "strict"
    types=["jpeg", "png", "pdf"],      # accepted file types
    limits={"max_size": 20_000_000, "scan_timeout": 5},
    wait=30,                           # answer within 30 s whatever the file does
)
```

With `wait`, a scan that has not ended in time is reported with `limit.time`, never clean,
and left running on its thread; `scanner.overdue` counts those, and above 0 the program is
due a restart. `sanitize` also takes `types`, `pdf_dpi`, `pdf_jpeg`, `pdf_text` and
`pdf_vector_text`.

`sanitize` scans and then writes a clean image anew from its pixels, so that nothing but the
picture is kept:

```python
try:
    image = scanner.sanitize(data, filename="a.png")
except malmal.SanitizeError:       # Rejected (with .report) or NotRebuilt
    reject()
else:
    store(image.data, image.file_type)
```

## Installing

A wheel from the [releases](https://github.com/nguyenthuan155632/malmal/releases) carries
the library, for x86-64 and ARM64 Linux with glibc 2.17 or newer:

```bash
pip install malmal-0.4.2-py3-none-manylinux2014_x86_64.whl
```

Such a wheel is built with `bindings/python/build_wheel.sh x86_64` (or `aarch64`), which
needs `pip install cargo-zigbuild ziglang` and the Rust target for that machine.

Anywhere else, the package needs `libmalmal_ffi`, which is built from the Rust sources:

```bash
cargo build --release -p malmal-ffi
```

```bash
cp target/release/libmalmal_ffi.so bindings/python/malmal/
```

```bash
pip install ./bindings/python
```

The copy placed in the package is installed with it. Alternatively leave the library where
it is and point `MALMAL_LIBRARY` at it, or pass `Scanner(library=...)`.

## Tests

```bash
MALMAL_LIBRARY=$PWD/target/release/libmalmal_ffi.so PYTHONPATH=bindings/python python3 -m unittest discover -s bindings/python/tests
```
