import hashlib
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
