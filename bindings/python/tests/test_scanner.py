import hashlib
import os
import struct
import threading
import unittest
import zlib

import malmal

GIF = (
    b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"
    b"\x02\x02\x4c\x01\x00\x3b"
)
ELF = b"\x7fELF\x02\x01\x01" + bytes(9)
PDF = b"%PDF-1.7\n1 0 obj\n<< >>\nendobj\ntrailer\n<< >>\n%%EOF\n"


def png_with_comment():
    """One transparent pixel, and a comment a rebuilt file does not keep."""

    def chunk(kind, body):
        crc = struct.pack(">I", zlib.crc32(kind + body))
        return struct.pack(">I", len(body)) + kind + body + crc

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
        + chunk(b"tEXt", b"Comment\0taken on holiday")
        + chunk(b"IDAT", zlib.compress(bytes(5)))
        + chunk(b"IEND", b"")
    )


class ScannerTest(unittest.TestCase):
    def test_verdicts(self):
        with malmal.Scanner() as scanner:
            report = scanner.scan(GIF, filename="a.gif", content_type="image/gif")
            self.assertTrue(report.clean)
            self.assertEqual(report.detected_type, "gif")
            self.assertEqual(report.sha256, hashlib.sha256(GIF).hexdigest())

            report = scanner.scan(ELF, filename="photo.jpg")
            self.assertEqual(report.verdict, "malicious")
            codes = [finding["code"] for finding in report.findings]
            self.assertIn("type.executable", codes)

            self.assertEqual(scanner.scan(b"plain text").verdict, "suspicious")
            self.assertEqual(scanner.scan(b"").verdict, "suspicious")
            self.assertTrue(scanner.scan(bytearray(GIF)).clean)

    def test_hashlist(self):
        digest = hashlib.sha256(GIF).hexdigest()
        with malmal.Scanner(hashlist=digest + "\n") as scanner:
            codes = [finding["code"] for finding in scanner.scan(GIF).findings]
            self.assertIn("hash.blocklisted", codes)
        with self.assertRaises(ValueError):
            malmal.Scanner(hashlist="not a digest")

    def test_pdf_passwords(self):
        corpus = os.path.join(os.path.dirname(__file__), "../../../tests/corpus/malicious")
        with open(os.path.join(corpus, "password-javascript.pdf"), "rb") as file:
            pdf = file.read()

        def encrypted(scanner):
            findings = scanner.scan(pdf).findings
            return next(f["severity"] for f in findings if f["code"] == "pdf.encrypted")

        with malmal.Scanner() as scanner:
            self.assertEqual(encrypted(scanner), "medium")
        with malmal.Scanner(pdf_passwords=["wrong", b"secret"]) as scanner:
            self.assertEqual(encrypted(scanner), "info")
        with self.assertRaises(ValueError):
            malmal.Scanner(pdf_passwords=["two\nlines"])

    def test_sanitize_documents(self):
        corpus = os.path.join(os.path.dirname(__file__), "../../../tests/corpus")

        def read(name):
            with open(os.path.join(corpus, name), "rb") as file:
                return file.read()

        svg = (
            b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'>"
            b"<rect width='4' height='4'/></svg>"
        )
        with malmal.Scanner() as scanner:
            # The scan sees the handler and that is the end of it.
            with self.assertRaises(malmal.Rejected):
                scanner.sanitize(svg, filename="a.svg")
            drawing = scanner.sanitize(read("clean/square.svg"), filename="a.svg")
            self.assertEqual((drawing.file_type, drawing.width, drawing.frames), ("svg", 0, 1))
            self.assertIn(b"<rect", drawing.data)

            # Only a library built with the `cdr-pdf` feature takes these.
            try:
                pages = scanner.sanitize(read("clean/page.pdf"), filename="a.pdf")
            except malmal.NotRebuilt as refused:
                self.assertIn("not a type this build rebuilds", str(refused))
            else:
                self.assertEqual((pages.file_type, pages.width, pages.frames), ("pdf", 0, 1))
                self.assertTrue(pages.data.startswith(b"%PDF-1.7"))
                self.assertTrue(scanner.scan(pages.data).clean)

            # Clean to a scan; rebuilt, its pixels are a PDF. See the corpus test.
            with self.assertRaises(malmal.Rejected) as raised:
                scanner.sanitize(read("clean/pixels-spell-pdf.png"))
            self.assertIn("image.polyglot", str(raised.exception))

    def test_closed_scanner(self):
        scanner = malmal.Scanner(strict=True)
        scanner.close()
        scanner.close()
        with self.assertRaises(malmal.ScanError):
            scanner.scan(GIF)
        with self.assertRaises(malmal.ScanError):
            scanner.sanitize(GIF)

    def test_sanitize(self):
        upload = png_with_comment()
        self.assertIn(b"holiday", upload)
        with malmal.Scanner() as scanner:
            image = scanner.sanitize(upload, filename="a.png", content_type="image/png")
            self.assertTrue(image.data.startswith(b"\x89PNG"))
            self.assertNotIn(b"holiday", image.data)
            self.assertEqual(
                (image.file_type, image.width, image.height, image.frames), ("png", 1, 1, 1)
            )
            self.assertTrue(image.report.clean)
            self.assertEqual(image.report.sha256, hashlib.sha256(upload).hexdigest())
            self.assertTrue(scanner.scan(image.data).clean)

            self.assertEqual(scanner.sanitize(upload, jpeg_quality=0).data, image.data)

            with self.assertRaises(malmal.Rejected) as raised:
                scanner.sanitize(ELF, filename="photo.jpg")
            self.assertEqual(raised.exception.report.verdict, "malicious")
            self.assertIn("type.executable", str(raised.exception))

            with self.assertRaises(malmal.NotRebuilt):
                scanner.sanitize(PDF)
            for error in (malmal.Rejected, malmal.NotRebuilt):
                self.assertTrue(issubclass(error, malmal.SanitizeError))

    def test_threads(self):
        scanner = malmal.Scanner()
        verdicts = []
        workers = [
            threading.Thread(target=lambda: verdicts.append(scanner.scan(GIF).verdict))
            for _ in range(8)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(verdicts, ["clean"] * 8)


if __name__ == "__main__":
    unittest.main()
