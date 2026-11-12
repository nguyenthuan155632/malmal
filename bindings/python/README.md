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

## Installing

The package needs `libmalmal_ffi`, which is built from the Rust sources:

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
