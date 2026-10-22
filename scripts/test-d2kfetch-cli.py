#!/usr/bin/env python3
"""Проверка контракта d2kfetch только на локальных адресах."""
import json
from pathlib import Path
import socket
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
FETCH = ROOT / "core" / "d2kfetch"


class FetchContract(unittest.TestCase):
    def test_version(self):
        result = subprocess.run([str(FETCH), "--version"], capture_output=True,
                                text=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("d2kfetch "))

    def test_empty_address_does_not_fall_back_to_dns(self):
        result = subprocess.run([str(FETCH), "--name", "localhost", "--ip", "",
                                 "--quic", "--json"], capture_output=True,
                                text=True, timeout=3)
        data = json.loads(result.stdout)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(data["schema"], 2)
        self.assertEqual(data["shape"], "dns_failed")
        self.assertFalse(data["measured"])

    def test_quic_bytes_are_not_reported_as_http_body(self):
        result = subprocess.run([str(FETCH), "--name", "stand.example", "--ip",
                                 "127.0.0.1", "--port", "1", "--quic",
                                 "--deadline", "100", "--json"],
                                capture_output=True, text=True, timeout=10)
        data = json.loads(result.stdout)
        self.assertIsNone(data["body_bytes"])
        self.assertIsInstance(data["quic_stream_bytes"], int)
        self.assertFalse(data["headers_inspected"])
        self.assertIsNone(data["location"])

    def test_failed_ladder_reports_both_measurements(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            result = subprocess.run([str(FETCH), "--name", "stand.example", "--ip",
                                     "127.0.0.1", "--port", str(sock.getsockname()[1]),
                                     "--ladder", "--json"], capture_output=True,
                                    text=True, timeout=10)
        data = json.loads(result.stdout)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(data["verdict"], "unreachable")
        self.assertFalse(data["tx_passed"])
        for field in ("rx_cut", "rx_short", "rx_unmeasured", "rx_direct_complete",
                      "rx_tls_unavailable"):
            self.assertIsInstance(data[field], bool)
        self.assertIsInstance(data["measured_path"], str)
        self.assertIsInstance(data["rx_reason"], str)


if __name__ == "__main__":
    unittest.main()
