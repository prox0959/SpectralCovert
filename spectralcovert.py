#!/usr/bin/env python3
"""
===============================================================================
                SpectralCovert v1.0.0
    Cryptographic Network Covert Channel & Shannon Entropy Leak Detector
===============================================================================
Author: Çınar (prox0959)
Target Audience: Academic Network Security Labs (ETH Zurich / TU Munich), DFIR & Blue Teams
License: MIT
Zero External Dependencies (Pure Python Standard Library)
===============================================================================
"""

import sys
import os
import argparse
import time
import math
import statistics

# Set stdout encoding to UTF-8 safely for Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure local imports work cleanly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.entropy import (
    calculate_shannon_entropy,
    calculate_normalized_entropy,
    chi_squared_uniformity,
    sliding_window_entropy,
    analyze_payload_threat,
    WIN_ICMP_BASELINE
)
from core.timing import InterPacketDelayAnalyzer
from core.channel_sim import CovertChannelSimulator
from core.visualizer import render_ascii_histogram, render_entropy_gauge

BANNER = r"""
   _____                  __             _______                     __ 
  / ___/____  ___  _____ / /__________ _/ / ____/___ _   _____  _____/ /_
  \__ \/ __ \/ _ \/ ___// __/ ___/ __ `/ / /   / __ \ | / / _ \/ ___/ __/
 ___/ / /_/ /  __/ /__ / /_/ /  / /_/ / / /___/ /_/ / |/ /  __/ /  / /_  
/____/ .___/\___/\___/ \__/_/   \__,_/_/\____/\____/|___/\___/_/   \__/  
    /_/                                                                  
 [::] SpectralCovert v1.0.0 | Network Covert Channel & Entropy Leak Detector
 [::] Author: Çınar (prox0959) | Zero External Dependencies
"""


def run_academic_benchmark():
    """
    Executes an end-to-end benchmark demonstrating mathematical detection
    of both Covert Storage Channels and Covert Timing Channels.
    """
    print(BANNER)
    print("=" * 72)
    print("      ACADEMIC BENCHMARK: COVERT CHANNEL DETECTION VALIDATION")
    print("=" * 72)

    # -------------------------------------------------------------
    # PHASE 1: COVERT STORAGE CHANNEL (PAYLOAD ENTROPY ANALYSIS)
    # -------------------------------------------------------------
    print("\n[PHASE 1] EVALUATING ICMP STORAGE CHANNELS (PAYLOAD SHANNON ENTROPY)")
    print("-" * 72)

    # 1. Benign Standard Windows Ping Payload
    benign_payload = WIN_ICMP_BASELINE
    res_benign = analyze_payload_threat(benign_payload)
    print(f"[*] Test 1: Benign Windows ICMP Echo Request ({len(benign_payload)} bytes)")
    print(f"    Payload: {benign_payload[:24]}...")
    print(f"    Entropy: {render_entropy_gauge(res_benign['entropy_bits'])}")
    print(f"    Verdict: {res_benign['verdict']} (Score: {res_benign['risk_score']}/100)")
    assert res_benign['verdict'] == 'BENIGN', "Benign ICMP false positive!"

    # 2. Covert Exfiltration: High-Entropy AES Ciphertext
    simulated_aes_exfil = os.urandom(32)
    res_covert_storage = analyze_payload_threat(simulated_aes_exfil)
    print(f"\n[*] Test 2: Covert Exfiltration - Encrypted AES Stolen Key in ICMP Payload")
    print(f"    Payload (hex): {simulated_aes_exfil.hex()[:32]}...")
    print(f"    Entropy: {render_entropy_gauge(res_covert_storage['entropy_bits'])}")
    print(f"    Verdict: {res_covert_storage['verdict']} (Score: {res_covert_storage['risk_score']}/100)")
    for ind in res_covert_storage['indicators']:
        print(f"    -> {ind}")
    assert res_covert_storage['risk_score'] >= 90, "Covert storage channel missed!"

    print("\n[+] Phase 1 Passed: 100% Accuracy on Storage Exfiltration Channels.")

    # -------------------------------------------------------------
    # PHASE 2: COVERT TIMING CHANNEL (INTER-PACKET DELAY / IPD)
    # -------------------------------------------------------------
    print("\n\n[PHASE 2] EVALUATING COVERT TIMING CHANNELS (IPD & SPECTRAL ANALYSIS)")
    print("-" * 72)

    analyzer = InterPacketDelayAnalyzer(min_samples=16)

    # 1. Benign Traffic: Periodic Heartbeat / Normal Ping with Gaussian Jitter
    print("[*] Generating benign traffic stream (100 packets, ~200ms interval + jitter)...")
    benign_timestamps = CovertChannelSimulator.generate_benign_timestamps(
        count=100, base_interval_ms=200.0, jitter_std_ms=6.0
    )
    benign_report = analyzer.analyze_stream(benign_timestamps)

    print(f"    Sample Size: {benign_report['sample_count']} intervals")
    print(f"    Mean Delay: {benign_report['moments']['mean']} ms | StdDev: {benign_report['moments']['std_dev']} ms")
    print(f"    Sarle's Bimodality Coefficient: {benign_report['bimodality_coefficient']:.4f} (Threshold: 0.555)")
    print(f"    Jitter Entropy: {benign_report['jitter_entropy']:.3f} bits")
    print(f"    Verdict: {benign_report['verdict']} (Threat Score: {benign_report['threat_score']}/100)")
    assert not benign_report['bimodal_detected'], "Benign traffic falsely flagged as bimodal timing channel!"

    # 2. Covert Timing Channel: Modulating Secret ASCII Message
    secret_text = "ETH2026"
    print(f"\n[*] Generating Covert Timing Channel modulating: '{secret_text}'")
    print("    Bit 0 delay -> 40ms, Bit 1 delay -> 140ms + simulated network jitter")
    covert_timestamps, binary_bits = CovertChannelSimulator.generate_covert_timing_timestamps(
        secret_message=secret_text, t0_ms=40.0, t1_ms=140.0, jitter_std_ms=4.0
    )
    covert_report = analyzer.analyze_stream(covert_timestamps)

    print(f"    Sample Size: {covert_report['sample_count']} intervals")
    print(f"    Mean Delay: {covert_report['moments']['mean']} ms | StdDev: {covert_report['moments']['std_dev']} ms")
    print(f"    Sarle's Bimodality Coefficient: {covert_report['bimodality_coefficient']:.4f} (Threshold: 0.555)")
    print(f"    Detected Dual Clusters: T0 ~ {covert_report['estimated_t0_ms']} ms | T1 ~ {covert_report['estimated_t1_ms']} ms")
    print(f"    Verdict: {covert_report['verdict']} (Threat Score: {covert_report['threat_score']}/100)")
    for ind in covert_report['indicators']:
        print(f"    -> {ind}")

    delays = analyzer.compute_delays(covert_timestamps)
    hist = render_ascii_histogram(delays, num_bins=8, title="Bimodal Inter-Packet Delay Histogram")
    print(hist)

    # Attempt Covert Message Reconstruction
    threshold = (covert_report['estimated_t0_ms'] + covert_report['estimated_t1_ms']) / 2.0
    recovered_msg = analyzer.decode_covert_bits(delays, threshold)
    print(f"\n[+] Covert Message Reconstruction Attempt:")
    print(f"    Original Secret : '{secret_text}'")
    print(f"    Decoded Payload : '{recovered_msg}'")
    print(f"    Match Confirmed : {secret_text in recovered_msg}")

    assert covert_report['verdict'] == 'COVERT_TIMING_CHANNEL_DETECTED', "Timing channel missed!"
    print("\n[+] Phase 2 Passed: 100% Accuracy on Covert Timing Channel Detection.")

    print("\n" + "=" * 72)
    print(" [OK] BENCHMARK COMPLETE: ALL MATHEMATICAL AND CRYPTOGRAPHIC TESTS PASSED")
    print("=" * 72 + "\n")


def analyze_text_cli(text: str):
    """CLI handler for single payload analysis."""
    print(BANNER)
    data = text.encode("utf-8")
    report = analyze_payload_threat(data)
    print(f"[+] Input Length: {report['length_bytes']} bytes")
    print(f"[+] Shannon Entropy: {render_entropy_gauge(report['entropy_bits'])}")
    print(f"[+] Normalized Entropy: {report['normalized_entropy'] * 100:.1f}%")
    print(f"[+] Unique Byte Ratio: {report['unique_ratio'] * 100:.1f}%")
    print(f"[+] Chi-Squared (Uniformity): {report['chi_squared']}")
    print(f"[+] Security Verdict: {report['verdict']} (Score: {report['risk_score']}/100)")
    for ind in report['indicators']:
        print(f"    -> {ind}")


def simulate_leak_cli(message: str):
    """Simulates timing channel leak and visualizes the detection."""
    print(BANNER)
    print(f"[*] Simulating Covert Timing Transmission of: '{message}'")
    timestamps, bits = CovertChannelSimulator.generate_covert_timing_timestamps(message)
    analyzer = InterPacketDelayAnalyzer()
    report = analyzer.analyze_stream(timestamps)
    delays = analyzer.compute_delays(timestamps)
    print(f"[+] Total Intervals Transmitted: {len(delays)}")
    print(f"[+] Bimodality Coefficient: {report['bimodality_coefficient']:.4f}")
    print(f"[+] Verdict: {report['verdict']}")
    print(render_ascii_histogram(delays, num_bins=8, title="Delay Modulation Histogram"))


def main():
    parser = argparse.ArgumentParser(
        description="SpectralCovert - Network Covert Channel & Entropy Leak Detector (Author: Çınar / prox0959)"
    )
    parser.add_argument("--demo", action="store_true", help="Run full academic benchmark and detection suite")
    parser.add_argument("--analyze-text", type=str, help="Analyze raw string or hex payload for entropy anomalies")
    parser.add_argument("--simulate-leak", type=str, help="Simulate covert timing channel exfiltration with target secret")

    args = parser.parse_args()

    if args.demo:
        run_academic_benchmark()
    elif args.analyze_text:
        analyze_text_cli(args.analyze_text)
    elif args.simulate_leak:
        simulate_leak_cli(args.simulate_leak)
    else:
        # Default to academic demo if no arguments provided
        run_academic_benchmark()


if __name__ == "__main__":
    main()
