"""
SpectralCovert Unit Test Suite
Validates mathematical calculations, entropy bounds, and timing channel detection.
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.entropy import (
    calculate_shannon_entropy,
    calculate_normalized_entropy,
    chi_squared_uniformity,
    analyze_payload_threat,
    WIN_ICMP_BASELINE
)
from core.timing import InterPacketDelayAnalyzer
from core.channel_sim import CovertChannelSimulator


class TestSpectralCovert(unittest.TestCase):

    def test_shannon_entropy_bounds(self):
        # Empty data
        self.assertEqual(calculate_shannon_entropy(b""), 0.0)
        # Uniform repeated byte: zero entropy
        self.assertEqual(calculate_shannon_entropy(b"\x00" * 64), 0.0)
        # All 256 byte values once: exactly 8.0 bits
        full_byte_space = bytes(range(256))
        self.assertAlmostEqual(calculate_shannon_entropy(full_byte_space), 8.0, places=2)

    def test_normalized_entropy(self):
        # 32 random bytes should have high normalized entropy
        random_bytes = os.urandom(32)
        norm_h = calculate_normalized_entropy(random_bytes)
        self.assertGreaterEqual(norm_h, 0.88)
        self.assertLessEqual(norm_h, 1.0)

    def test_known_windows_ping_baseline(self):
        report = analyze_payload_threat(WIN_ICMP_BASELINE)
        self.assertEqual(report["verdict"], "BENIGN")
        self.assertEqual(report["risk_score"], 0)

    def test_encrypted_exfiltration_alert(self):
        # Pseudo-random encrypted payload
        encrypted_token = os.urandom(32)
        report = analyze_payload_threat(encrypted_token)
        self.assertEqual(report["verdict"], "ALERT_COVERT_EXFILTRATION")
        self.assertEqual(report["risk_score"], 95)

    def test_timing_channel_detection_and_decoding(self):
        analyzer = InterPacketDelayAnalyzer(min_samples=16)
        secret = "ETH"
        timestamps, bits = CovertChannelSimulator.generate_covert_timing_timestamps(
            secret_message=secret, t0_ms=40.0, t1_ms=140.0, jitter_std_ms=2.0
        )
        report = analyzer.analyze_stream(timestamps)
        self.assertEqual(report["verdict"], "COVERT_TIMING_CHANNEL_DETECTED")
        self.assertGreater(report["bimodality_coefficient"], 0.555)

        delays = analyzer.compute_delays(timestamps)
        threshold = (report["estimated_t0_ms"] + report["estimated_t1_ms"]) / 2.0
        recovered = analyzer.decode_covert_bits(delays, threshold)
        self.assertIn(secret, recovered)


if __name__ == "__main__":
    unittest.main()
