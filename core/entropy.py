"""
SpectralCovert - Shannon Entropy & Statistical Distribution Engine
Author: Çınar (prox0959)
License: MIT

Zero external dependencies. Implements Shannon Entropy, Sample-Length Normalized
Entropy, Chi-Squared uniformity testing, and OS ICMP baseline pattern matching.
"""

import math
from collections import Counter
from typing import Dict, List, Tuple, Any

# TR: Windows ping komutunun (ping.exe) standart gönderdiği 32-byte payload deseni
WIN_ICMP_BASELINE = b"abcdefghijklmnopqrstuvwabcdefghi"

# TR: Linux iputils ping paketinin ilk baytları
LINUX_ICMP_CHARS = b"!\"#$%&'()*+,-./01234567"


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates the standard Shannon Information Entropy of a byte sequence in bits per byte.
    H(X) = - sum( P(x_i) * log2(P(x_i)) )
    Theoretical maximum for 256 discrete symbols is 8.0 bits.
    Note: For a sequence of length N, H(X) cannot exceed log2(N).
    
    # TR: Shannon Entropisi: Verideki belirsizlik ve bilgi yoğunluğu ölçüsü.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def calculate_normalized_entropy(data: bytes) -> float:
    """
    Computes sample-length normalized entropy: H(X) / min(8.0, log2(N)).
    Returns a score from 0.0 to 1.0 representing how close the sample is
    to maximum theoretical randomness for its given size.
    
    # TR: Normalize Entropi: Küçük paketlerde (örn: 32 byte) maksimum entropi
    # log2(32) = 5.0 bit ile sınırlıdır. Bu fonksiyon boyuttan bağımsız 0.0 - 1.0
    # arası standart bir rastgelelik oranı üretir.
    """
    if len(data) <= 1:
        return 0.0

    raw_h = calculate_shannon_entropy(data)
    max_h = min(8.0, math.log2(len(data)))
    
    if max_h == 0:
        return 0.0

    return round(min(1.0, raw_h / max_h), 4)


def chi_squared_uniformity(data: bytes) -> float:
    """
    Calculates the Chi-Squared (X^2) statistic of byte frequencies against uniform distribution.
    X^2 = sum( (Observed - Expected)^2 / Expected )
    """
    if len(data) < 16:
        return 0.0

    observed = Counter(data)
    expected = len(data) / 256.0

    chi_sq = 0.0
    for byte_val in range(256):
        obs = observed.get(byte_val, 0)
        chi_sq += ((obs - expected) ** 2) / expected

    return round(chi_sq, 2)


def sliding_window_entropy(data: bytes, window_size: int = 16, step: int = 4) -> List[float]:
    """
    Computes sliding-window Shannon entropy to identify high-density bursts.
    """
    if len(data) < window_size:
        return [calculate_shannon_entropy(data)]

    scores = []
    for i in range(0, len(data) - window_size + 1, step):
        window = data[i:i + window_size]
        scores.append(calculate_shannon_entropy(window))

    return scores


def is_known_benign_icmp(payload: bytes) -> Tuple[bool, str]:
    """
    Compares payload against known benign operating system ICMP patterns.
    """
    if not payload:
        return True, "EMPTY_PAYLOAD"

    if payload == WIN_ICMP_BASELINE:
        return True, "WINDOWS_DEFAULT_PING"

    if len(set(payload)) == 1:
        return True, "UNIFORM_REPEATED_BYTE"

    if len(payload) >= 8 and all(payload[i] + 1 == payload[i + 1] for i in range(min(len(payload) - 1, 8))):
        return True, "SEQUENTIAL_ASCII_PROBE"

    return False, "NON_STANDARD_PAYLOAD"


def analyze_payload_threat(payload: bytes) -> Dict[str, Any]:
    """
    Evaluates payload entropy and characteristics to classify whether a covert
    storage channel or encrypted exfiltration is occurring.
    """
    raw_entropy = calculate_shannon_entropy(payload)
    norm_entropy = calculate_normalized_entropy(payload)
    chi_sq = chi_squared_uniformity(payload)
    is_benign_sig, sig_name = is_known_benign_icmp(payload)
    
    unique_ratio = len(set(payload)) / len(payload) if payload else 0.0

    verdict = "BENIGN"
    risk_score = 0
    indicators = []

    if is_benign_sig:
        verdict = "BENIGN"
        risk_score = 0
        indicators.append(f"Matched legitimate OS signature: {sig_name}")
    else:
        # If payload exhibits near-perfect theoretical randomness for its size
        # and has high byte diversity without OS signature
        if norm_entropy >= 0.90 and unique_ratio >= 0.80 and len(payload) >= 16:
            verdict = "ALERT_COVERT_EXFILTRATION"
            risk_score = 95
            indicators.append(
                f"Near-maximum entropy density ({norm_entropy * 100:.1f}% of theoretical limit, {raw_entropy:.3f} bits/byte)"
            )
            indicators.append(
                f"Abnormal byte diversity ({unique_ratio * 100:.1f}% unique symbols) - High confidence encrypted payload"
            )
        elif norm_entropy >= 0.82:
            verdict = "SUSPICIOUS_PAYLOAD"
            risk_score = 65
            indicators.append(f"Elevated normalized entropy ({norm_entropy * 100:.1f}%) - potential obfuscated/base64 data")
        elif len(payload) > 64:
            verdict = "ANOMALOUS_SIZE"
            risk_score = 40
            indicators.append(f"Abnormal ICMP payload length ({len(payload)} bytes) without standard OS header")
        else:
            verdict = "BENIGN_CUSTOM"
            risk_score = 15
            indicators.append(f"Non-standard payload with moderate entropy ({raw_entropy:.3f} bits/byte)")

    return {
        "length_bytes": len(payload),
        "entropy_bits": raw_entropy,
        "normalized_entropy": norm_entropy,
        "unique_ratio": round(unique_ratio, 3),
        "chi_squared": chi_sq,
        "verdict": verdict,
        "risk_score": risk_score,
        "indicators": indicators,
        "signature": sig_name
    }
