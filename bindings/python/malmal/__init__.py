"""Python interface to the malmal upload scanner.

The scanner itself is the C library built from the ``malmal-ffi`` crate;
this module loads it with :mod:`ctypes`. Anything but a clean verdict,
including an exception, means the file is not accepted::

    import malmal

    scanner = malmal.Scanner()
    report = scanner.scan(data, filename="a.png", content_type="image/png")
    if not report.clean:
        raise ValueError([finding["code"] for finding in report.findings])
"""

import ctypes
import ctypes.util
import json
import os
from dataclasses import dataclass, field

__all__ = ["Report", "ScanError", "Scanner"]

_VERDICTS = ("clean", "suspicious", "malicious")
_ERROR = 3


class ScanError(Exception):
    """The file was not scanned. Treat it as not accepted."""


@dataclass(frozen=True)
class Report:
    """What a scan found; the fields are those of the Rust ``Report``."""

    verdict: str
    detected_type: str
    declared_types: list = field(default_factory=list)
    size: int = 0
    sha256: str = ""
    findings: list = field(default_factory=list)

    @property
    def clean(self):
        return self.verdict == "clean"


def _load(path):
    """Open the library: the given path, ``MALMAL_LIBRARY``, a copy placed
    next to this file, or whatever the system loader finds."""
    here = os.path.dirname(os.path.abspath(__file__))
    bundled = [
        os.path.join(here, name)
        for name in ("libmalmal_ffi.so", "libmalmal_ffi.dylib", "malmal_ffi.dll")
    ]
    candidates = [path, os.environ.get("MALMAL_LIBRARY")]
    candidates += [name for name in bundled if os.path.exists(name)]
    candidates.append(ctypes.util.find_library("malmal_ffi"))
    for candidate in candidates:
        if candidate:
            library = ctypes.CDLL(candidate)
            break
    else:
        raise OSError(
            "libmalmal_ffi was not found; build it with `cargo build --release "
            "-p malmal-ffi` and set MALMAL_LIBRARY to its path"
        )
    library.malmal_scanner_new.restype = ctypes.c_void_p
    library.malmal_scanner_new.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
    library.malmal_scanner_free.restype = None
    library.malmal_scanner_free.argtypes = [ctypes.c_void_p]
    library.malmal_scan.restype = ctypes.c_int
    library.malmal_scan.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.malmal_string_free.restype = None
    library.malmal_string_free.argtypes = [ctypes.c_void_p]
    return library


class Scanner:
    """A configured scanner. One instance may be shared between threads;
    the interpreter lock is released while a file is scanned.

    ``strict`` selects the strict policy. ``hashlist`` is an optional
    SHA-256 blocklist as text, one hex digest per line. ``library`` is the
    path of ``libmalmal_ffi``, when it is not found otherwise.
    """

    def __init__(self, strict=False, hashlist=None, library=None):
        self._library = _load(library)
        blocklist = hashlist.encode() if isinstance(hashlist, str) else hashlist
        self._handle = self._library.malmal_scanner_new(
            int(strict), blocklist, len(blocklist) if blocklist else 0
        )
        if not self._handle:
            raise ValueError("the hash list does not parse")

    def scan(self, data, filename=None, content_type=None):
        """Scan ``data`` (bytes). ``filename`` and ``content_type`` are what
        the uploader claimed. Returns a :class:`Report`; raises
        :class:`ScanError` if the file could not be scanned."""
        if not self._handle:
            raise ScanError("the scanner is closed")
        data = bytes(data)
        encoded = [
            None if text is None else text.replace("\0", "").encode()
            for text in (filename, content_type)
        ]
        report = ctypes.c_void_p()
        verdict = self._library.malmal_scan(
            self._handle, data, len(data), encoded[0], encoded[1], ctypes.byref(report)
        )
        try:
            if verdict == _ERROR or not report.value:
                raise ScanError("the scanner failed; the file was not scanned")
            fields = json.loads(ctypes.string_at(report.value))
        finally:
            self._library.malmal_string_free(report)
        known = {name: fields[name] for name in Report.__dataclass_fields__ if name in fields}
        return Report(**known)

    def close(self):
        if self._handle:
            self._library.malmal_scanner_free(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        self.close()
