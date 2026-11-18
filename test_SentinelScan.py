import importlib.util
import tempfile
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "sentinelscan",
    Path(__file__).with_name("SentinelScan.py"),
)
sentinelscan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sentinelscan)


class SentinelScanTests(unittest.TestCase):
    def test_parser_accepts_documented_formats(self):
        parser = sentinelscan.build_parser()
        for report_format in ("txt", "json", "csv", "html", "both", "all"):
            args = parser.parse_args(["--target", "localhost", "--format", report_format])
            self.assertEqual(args.format, report_format)

    def test_validate_port(self):
        self.assertTrue(sentinelscan.validate_port(1))
        self.assertTrue(sentinelscan.validate_port(65535))
        self.assertFalse(sentinelscan.validate_port(0))
        self.assertFalse(sentinelscan.validate_port(65536))
        self.assertFalse(sentinelscan.validate_port("80"))

    def test_parse_banner_service_version(self):
        service, version = sentinelscan.parse_banner_service_version("OpenSSH_6.7")
        self.assertEqual(service, "openssh")
        self.assertEqual(version, "6.7")

    def test_version_matches_substring_and_ranges(self):
        self.assertTrue(sentinelscan.version_matches("6.7", "6."))
        self.assertTrue(sentinelscan.version_matches("6.7", ">=6.0,<7.0"))
        self.assertFalse(sentinelscan.version_matches("7.4", ">=6.0,<7.0"))
        self.assertTrue(sentinelscan.version_matches("6.7", ">6.0,<7.0"))
        self.assertTrue(sentinelscan.version_matches("6.7", "<7.0"))
        self.assertFalse(sentinelscan.version_matches("7.0", "<7.0"))

    def test_csv_banner_formula_is_neutralized(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.txt"
            payload = {
                "target": "localhost",
                "ip": "127.0.0.1",
                "duration": 0.1,
                "ports": {"tcp/80": {"open": True, "banner": "=HYPERLINK(\"https://example.com\")"}},
                "vuln_matches": [],
            }
            csv_path = sentinelscan.write_csv_report(payload, report)
            csv_text = csv_path.read_text(encoding="utf-8")
            self.assertIn("'=HYPERLINK", csv_text)

    def test_csv_banner_leading_whitespace_formula_is_neutralized(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.txt"
            payload = {
                "target": "localhost",
                "ip": "127.0.0.1",
                "duration": 0.1,
                "ports": {"tcp/80": {"open": True, "banner": "  =SUM(1,1)"}},
                "vuln_matches": [],
            }
            csv_path = sentinelscan.write_csv_report(payload, report)
            csv_text = csv_path.read_text(encoding="utf-8")
            self.assertIn("'  =SUM", csv_text)

    def test_vulnerability_requires_service_and_version(self):
        matches = sentinelscan.vuln_analysis_from_banners_txt(
            {"tcp/22": "OpenSSH_6.7", "tcp/80": "nginx/1.27.0"}
        )
        self.assertTrue(matches)
        self.assertTrue(all(match["service"] == "openssh" for match in matches))

    def test_json_report_writes_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.txt"
            payload = {
                "target": "localhost",
                "ip": "127.0.0.1",
                "duration": 0.1,
                "ports": {},
                "vuln_matches": [],
            }
            json_path = sentinelscan.write_json_report(payload, report)
            self.assertTrue(json_path.exists())
            import json

            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["target"], "localhost")

    def test_csv_report_writes_port_status(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.txt"
            payload = {
                "target": "localhost",
                "ip": "127.0.0.1",
                "duration": 0.1,
                "ports": {
                    "tcp/22": {"open": True, "banner": "OpenSSH_6.7"},
                    "udp/53": {"open": False, "banner": "open|filtered"},
                },
                "vuln_matches": [],
            }
            csv_path = sentinelscan.write_csv_report(payload, report)
            csv_text = csv_path.read_text(encoding="utf-8")
            self.assertIn("tcp,22,open,OpenSSH_6.7", csv_text)
            self.assertIn("udp,53,open|filtered,open|filtered", csv_text)

    def test_html_report_is_standalone_and_escaped(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.txt"
            payload = {
                "target": "<localhost>",
                "ip": "127.0.0.1",
                "duration": 0.1,
                "ports": {"tcp/80": {"open": True, "banner": "<Nginx>"}},
                "vuln_matches": [],
            }
            html_path = sentinelscan.write_html_report(payload, report)
            html_text = html_path.read_text(encoding="utf-8")
            self.assertIn("&lt;localhost&gt;", html_text)
            self.assertIn("&lt;Nginx&gt;", html_text)


if __name__ == "__main__":
    unittest.main()
