import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ot_pcap_triage.analyzer import _proto, _ev, analyze_pcap
from ot_pcap_triage.cli import _derive_extended_protocol_candidates, _derive_traffic_timeline, _preflight_output_dir, main
from ot_pcap_triage.reports import render_reports
from ot_pcap_triage.tshark import Tshark, TsharkError
from ot_pcap_triage.utils import is_public_ip, redact
from pcap_fixture import write_fixture


def row(i, src="10.0.0.2", dst="10.0.0.3", protocol="modbus", sport="49152", dport="502", transport="tcp", **extra):
    ip_version = "ipv6" if ":" in src else "ip"
    return {"frame.number": str(i), "frame.time_epoch": str(1700000000 + i), "frame.len": "60", f"{ip_version}.src": src, f"{ip_version}.dst": dst, f"{transport}.srcport": sport, f"{transport}.dstport": dport, "frame.protocols": f"eth:{ip_version}:{transport}:{protocol}", **extra}


class FakeTshark:
    def __init__(self, rows):
        self.rows = rows
    def iter_fields(self, *args, **kwargs):
        yield from self.rows
    def count_and_evidence(self, *args, **kwargs):
        return 0, []
    def raw_protocol_hierarchy(self, *args):
        return ""


class RegressionTests(unittest.TestCase):
    def test_decoded_over_port(self):
        self.assertEqual(_proto(row(1, protocol="http")), "HTTP")
        self.assertEqual(_proto(row(1, protocol="data")), "UNKNOWN")
        self.assertEqual(_proto(row(1, protocol="tpkt:cotp")), "COTP")
        self.assertEqual(_proto(row(1, protocol="iec60870_104")), "IEC104")

    def test_redaction_and_no_raw_info(self):
        for value in ["x", "password", "1234567890123", "secret" * 20]:
            self.assertEqual(redact(value), "REDACTED")
        self.assertEqual(redact(""), "")
        self.assertNotIn("my-secret", str(_ev(row(1, **{"_ws.col.Info": "my-secret"}))))

    def test_ipv4_ipv6_public(self):
        for addr in ["8.8.8.8", "2606:4700:4700::1111"]:
            self.assertTrue(is_public_ip(addr))
        for addr in ["10.0.0.1", "100.64.0.1", "224.0.0.1", "192.0.2.1", "fd00::1", "fe80::1", "ff02::1", "::1", "::ffff:10.0.0.1"]:
            self.assertFalse(is_public_ip(addr), addr)

    def test_engine_error_and_streaming_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "engine.py"
            script.write_text('import sys\nprint("frame.number")\nprint("1")\nprint("failure", file=sys.stderr)\nsys.exit(1)\n')
            tshark = Tshark(sys.executable)
            with patch.object(tshark, "_field_args", return_value=[str(script)]):
                with self.assertRaises(TsharkError):
                    tshark.fields(Path("test.pcap"), ["frame.number"])
                with self.assertRaises(TsharkError):
                    tshark.evidence_rows(Path("test.pcap"), "dns", 1)
            script.write_text('print("frame.number")\nfor i in range(1000): print(i)\n')
            with patch.object(tshark, "_field_args", return_value=[str(script)]):
                count, evidence = tshark.count_and_evidence(Path("test.pcap"), "dns", 3)
                self.assertEqual(count, 1000)
                self.assertEqual(len(evidence), 3)

    def test_plc_full_stream_public_and_protocols(self):
        rows = [row(i) for i in range(1, 202)] + [row(202, src="10.0.0.9"), row(203, src="10.0.0.9"), row(204, dst="8.8.8.8", protocol="dns", transport="udp", dport="53", **{"dns.flags.response": "0"}), row(205, src="fd00::1", dst="2606:4700:4700::1111", protocol="dns", transport="udp", dport="53", **{"dns.flags.response": "0"}), row(206, dst="1.1.1.1", protocol="ntp", transport="udp", dport="123", **{"ntp.flags.mode": "3"}), row(207, protocol="http"), row(208, protocol="goose"), row(209, protocol="cip:cipsafety")]
        metadata = {"expected_communications": {"plc_allowed_talkers": [{"plc": "10.0.0.3", "allowed_sources": ["10.0.0.2"]}]}}
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "test.pcap"
            pcap.write_bytes(b"test")
            for limit in [1, 10]:
                summary, findings, _, _ = analyze_pcap(pcap, metadata, FakeTshark(rows), limit)
                by_id = {f["id"]: f for f in findings}
                self.assertEqual(by_id["OT-ICS-UNEXPECTED-PLC-TALKER"]["match_count"], 2)
                self.assertEqual(by_id["OT-ICS-UNEXPECTED-PLC-TALKER"]["evidence"][0]["frame_number"], "202")
                self.assertEqual(by_id["OT-NET-PUBLIC-IP"]["match_count"], 3)
                self.assertEqual(by_id["OT-NET-PUBLIC-DNS"]["match_count"], 2)
                self.assertEqual(by_id["OT-NET-PUBLIC-NTP"]["match_count"], 1)
                counts = {r["id"]: r["count"] for r in summary["rule_results"]}
                self.assertEqual(counts["OT-ICS-MODBUS"], 203)
                self.assertEqual(counts["OT-ICS-GOOSE"], 1)
                self.assertEqual(counts["OT-ICS-CIP-SAFETY"], 1)

    def test_port_candidate_transport_and_decoded_conflict(self):
        catalog = {"modbus": {"name": "Modbus", "ports": ["502/tcp"]}}
        conv = {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3", "dst_port": "502", "packets": 1, "bytes": 60}
        rows = [{**conv, "transport": "udp", "protocol": "UNKNOWN"}, {**conv, "transport": "tcp", "protocol": "HTTP"}, {**conv, "transport": "tcp", "protocol": "UNKNOWN"}]
        result = _derive_extended_protocol_candidates({"conversations": rows}, catalog)
        self.assertEqual(result[0]["packets"], 1)

    def test_report_html_escaping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "<script>alert(1)</script>".replace("/", "_")
            pcap.write_bytes(b"test")
            summary, findings, suggested, _ = analyze_pcap(pcap, {}, FakeTshark([]), 1)
            render_reports(root / "out", summary, findings, suggested, "<img src=x onerror=alert(1)>", [])
            html = (root / "out/report.html").read_text()
            self.assertNotIn("<img src=x onerror", html)
            self.assertIn("&lt;img src=x onerror", html)
            self.assertIn("&lt;script&gt;", html)

    def test_output_nonempty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "report.html").write_text("old")
            self.assertFalse(_preflight_output_dir(root)[0])

    def test_timeline_streaming_and_protocol_precedence(self):
        rows = [row(1, protocol="http"), row(2, protocol="modbus")]
        summary = {"pcap": {"frames": 2, "first_packet_time": "2023-11-14T22:13:21+00:00", "last_packet_time": "2023-11-14T22:13:22+00:00", "duration_seconds": 1}}
        result = _derive_traffic_timeline(Path("test"), FakeTshark(rows), summary)
        self.assertEqual(sum(result["series"]["HTTP"]), 1)
        self.assertEqual(sum(result["series"]["Modbus"]), 1)

    @unittest.skipUnless(shutil.which("tshark"), "TShark not installed")
    def test_real_tshark_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root / "fixture.pcap")
            self.assertEqual(main([str(root / "fixture.pcap"), "-o", str(root / "out"), "--max-evidence", "1"]), 0)
            findings = {f["id"]: f for f in json.loads((root / "out/findings.json").read_text())}
            self.assertEqual(findings["OT-NET-PUBLIC-IP"]["match_count"], 3)
            self.assertEqual(findings["OT-NET-PUBLIC-DNS"]["match_count"], 2)
            self.assertEqual(findings["OT-NET-PUBLIC-NTP"]["match_count"], 1)
            self.assertTrue((root / "out/report.html").exists())


if __name__ == "__main__":
    unittest.main()
