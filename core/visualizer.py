"""
SpectralCovert - Terminal Spectral Visualization & Histogram Formatter
Author: Çınar (prox0959)
License: MIT
"""

import math
from typing import List


def render_ascii_histogram(values: List[float], num_bins: int = 10, title: str = "Distribution Histogram") -> str:
    """
    Renders an ASCII frequency histogram of numeric values.
    Uses pure ASCII characters for cross-platform compatibility on Windows terminals.
    """
    if not values:
        return "No data points to render."

    min_val = min(values)
    max_val = max(values)

    if min_val == max_val:
        return f"All {len(values)} points identical at {min_val:.2f}"

    bin_width = (max_val - min_val) / num_bins
    counts = [0] * num_bins

    for v in values:
        idx = int((v - min_val) / bin_width)
        if idx >= num_bins:
            idx = num_bins - 1
        counts[idx] += 1

    max_count = max(counts) if max(counts) > 0 else 1
    max_bar_width = 25

    lines = [f"\n--- {title} ---"]
    for i in range(num_bins):
        low_bound = min_val + i * bin_width
        high_bound = low_bound + bin_width
        bar_len = int((counts[i] / max_count) * max_bar_width)
        bar = "#" * bar_len
        lines.append(f"{low_bound:6.1f} - {high_bound:6.1f} ms | {bar:<25} ({counts[i]})")

    return "\n".join(lines)


def render_entropy_gauge(entropy: float, max_entropy: float = 8.0) -> str:
    """
    Renders an ASCII gauge for Shannon entropy (0.0 to 8.0 bits/byte).
    """
    pct = min(1.0, max(0.0, entropy / max_entropy))
    total_slots = 20
    filled = int(pct * total_slots)
    empty = total_slots - filled

    gauge = f"[{'=' * filled}{'-' * empty}] {entropy:.3f} / 8.000 bits"
    if entropy >= 6.8:
        tag = "[CRITICAL RANDOMNESS / AES]"
    elif entropy >= 5.0:
        tag = "[ELEVATED / BASE64]"
    elif entropy >= 3.0:
        tag = "[NORMAL TEXT / OS PING]"
    else:
        tag = "[LOW / REDUNDANT PADDING]"

    return f"{gauge} {tag}"
