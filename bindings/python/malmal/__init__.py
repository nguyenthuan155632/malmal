"""Python interface to the malmal upload scanner.

The scanner itself is the C library built from the ``malmal-ffi`` crate;
this module loads it with :mod:`ctypes`. Anything but a clean verdict,
including an exception, means the file is not accepted::

    import malmal

    scanner = malmal.Scanner()
    report = scanner.scan(data, filename="a.png", content_type="image/png")
    if not report.clean:
        raise ValueError([finding["code"] for finding in report.findings])

:meth:`Scanner.sanitize` goes one step further and writes a clean image
anew from its pixels, so that nothing but the picture is kept::

    try:
        image = scanner.sanitize(data, filename="a.png")
    except malmal.SanitizeError:
        raise ValueError("not an image to keep")
    store(image.data, image.file_type)
"""

import ctypes
import ctypes.util
import json
import os
from dataclasses import dataclass, field

__all__ = [
    "NotRebuilt",
    "Rejected",
    "Report",
    "SanitizeError",
    "Sanitized",
    "ScanError",
    "Scanner",
]

_CLEAN = 0
_ERROR = 3
_NOT_REBUILT = 4


class ScanError(Exception):
    """The file was not scanned. Treat it as not accepted."""


class SanitizeError(Exception):
    """There is no rebuilt file, and the original is not to be kept in its
    place."""


class Rejected(SanitizeError):
    """The scan did not come back clean; ``report`` says why."""

    def __init__(self, report):
        codes = ", ".join(finding["code"] for finding in report.findings)
        super().__init__("file is not clean: " + codes)
        self.report = report


class NotRebuilt(SanitizeError):
    """The file is clean but is not of a type that can be rebuilt, is too
    large, or does not decode."""


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


@dataclass(frozen=True)
class Sanitized:
    """A file written anew from a clean upload: an image from its pixels,
    an SVG from what draws in it, a PDF as pictures of its pages."""

    data: bytes
    #: The type of ``data``, which is not always the type of the upload.
    file_type: str
    #: In pixels; 0 for an SVG or a PDF, which have no size in pixels.
    width: int
    height: int
    #: Frames of an animation or pages of a PDF; otherwise 1.
    frames: int
    #: The report on the upload.
    report: Report


def _report(fields):
    known = {name: fields[name] for name in Report.__dataclass_fields__ if name in fields}
    return Report(**known)


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
    library.malmal_scanner_new_with_passwords.restype = ctypes.c_void_p
    library.malmal_scanner_new_with_passwords.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
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
    library.malmal_sanitize.restype = ctypes.c_int
    library.malmal_sanitize.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.malmal_bytes_free.restype = None
    library.malmal_bytes_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    return library


def _claims(filename, content_type):
    return [
        None if text is None else text.replace("\0", "").encode()
        for text in (filename, content_type)
    ]


class Scanner:
    """A configured scanner. One instance may be shared between threads;
    the interpreter lock is released while a file is scanned.

    ``strict`` selects the strict policy. ``hashlist`` is an optional
    SHA-256 blocklist as text, one hex digest per line. ``library`` is the
    path of ``libmalmal_ffi``, when it is not found otherwise.
    ``pdf_passwords`` are passwords (``str`` or ``bytes``) to try on
    encrypted PDFs, each as user and as owner password.
    """

    def __init__(self, strict=False, hashlist=None, library=None, pdf_passwords=()):
        # Before anything is loaded: `close` runs even when this raises.
        self._handle = None
        passwords = [
            password.encode() if isinstance(password, str) else bytes(password)
            for password in pdf_passwords
        ]
        if any(b"\n" in password for password in passwords):
            raise ValueError("a password cannot contain a line break")
        passwords = b"\n".join(passwords)
        self._library = _load(library)
        blocklist = hashlist.encode() if isinstance(hashlist, str) else hashlist
        self._handle = self._library.malmal_scanner_new_with_passwords(
            int(strict),
            blocklist,
            len(blocklist) if blocklist else 0,
            passwords,
            len(passwords),
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
        encoded = _claims(filename, content_type)
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
        return _report(fields)

    def sanitize(self, data, filename=None, content_type=None, jpeg_quality=90):
        """Scan ``data`` and, if it is clean and of a type that can be,
        write it anew. Returns a :class:`Sanitized`, whose ``data`` is the
        file to keep in place of the upload.

        Raises :class:`Rejected` if the scan of the upload, or of the file
        made from it, did not come back clean; ``report`` is the one that
        was not. Raises :class:`NotRebuilt` if there is nothing to rebuild, and
        :class:`ScanError` if the file could not be scanned. In every case
        the upload is not to be kept."""
        if not self._handle:
            raise ScanError("the scanner is closed")
        data = bytes(data)
        encoded = _claims(filename, content_type)
        image, length, info = ctypes.c_void_p(), ctypes.c_size_t(), ctypes.c_void_p()
        status = self._library.malmal_sanitize(
            self._handle,
            data,
            len(data),
            encoded[0],
            encoded[1],
            int(jpeg_quality),
            ctypes.byref(image),
            ctypes.byref(length),
            ctypes.byref(info),
        )
        try:
            if status == _ERROR or not info.value:
                raise ScanError("the scanner failed; the file was not scanned")
            fields = json.loads(ctypes.string_at(info.value))
            if status == _NOT_REBUILT:
                raise NotRebuilt(fields.get("error", "the image was not rebuilt"))
            report = _report(fields["report"])
            if status != _CLEAN or not image.value:
                raise Rejected(report)
            rebuilt = ctypes.string_at(image.value, length.value)
        finally:
            self._library.malmal_bytes_free(image, length)
            self._library.malmal_string_free(info)
        return Sanitized(data=rebuilt, report=report, **fields["image"])

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
