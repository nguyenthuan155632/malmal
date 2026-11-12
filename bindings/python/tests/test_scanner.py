import hashlib
import threading
import unittest

import malmal

GIF = (
    b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"
    b"\x02\x02\x4c\x01\x00\x3b"
)
ELF = b"\x7fELF\x02\x01\x01" + bytes(9)


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
