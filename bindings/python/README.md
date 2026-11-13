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
`Scanner(pdf_passwords=["..."])` supplies passwords to try on encrypted PDFs.

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
pip install malmal-0.2.0-py3-none-manylinux2014_x86_64.whl
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
