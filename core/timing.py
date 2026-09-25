"""
SpectralCovert - Inter-Packet Delay (IPD) & Covert Timing Channel Detector
Author: Çınar (prox0959)
License: MIT

Zero external dependencies. Analyzes packet inter-arrival intervals using
statistical moments, Sarle's Bimodality Coefficient, and Jitter Entropy.
"""

import math
import statistics
from typing import List, Dict, Any, Tuple


class InterPacketDelayAnalyzer:
    """
    Analyzes packet timestamp streams to detect Covert Timing Channels (CTC).
    
    # TR: Zamanlama Kanalı Analizörü:
    # Paketlerin içeriklerine HİÇ bakmadan, sadece paketlerin GELİŞ SAATLERİ (aralıkları)
    # arasındaki ritmi inceleyerek veri sızdırılıp sızdırılmadığını tespit eder.
    """

    def __init__(self, min_samples: int = 16):
        self.min_samples = min_samples

    @staticmethod
    def compute_delays(timestamps: List[float]) -> List[float]:
        """
        Computes the inter-packet delays (IPD) in milliseconds from arrival timestamps.
        IPD_i = (t_i - t_{i-1}) * 1000 ms
        
        # TR: Paketler arası bekleme süreleri (milisaniye cinsinden Delta t).
        """
        if len(timestamps) < 2:
            return []
        
        delays = []
        for i in range(1, len(timestamps)):
            delta_ms = (timestamps[i] - timestamps[i - 1]) * 1000.0
            if delta_ms > 0:
                delays.append(round(delta_ms, 3))
        return delays

    @staticmethod
    def compute_moments(delays: List[float]) -> Dict[str, float]:
        """
        Calculates mean, standard deviation, and coefficient of variation (CV).
        CV = std_dev / mean
        
        # TR: İstatistiksel Momentler: Ortalama gecikme, standart sapma ve varyasyon katsayısı.
        """
        if not delays:
            return {"mean": 0.0, "std_dev": 0.0, "cv": 0.0, "min": 0.0, "max": 0.0}

        mean = statistics.mean(delays)
        std_dev = statistics.stdev(delays) if len(delays) > 1 else 0.0
        cv = (std_dev / mean) if mean > 0 else 0.0

        return {
            "mean": round(mean, 3),
            "std_dev": round(std_dev, 3),
            "cv": round(cv, 4),
            "min": round(min(delays), 3),
            "max": round(max(delays), 3),
        }

    @staticmethod
    def bimodality_coefficient(delays: List[float]) -> float:
        """
        Calculates Sarle's Bimodality Coefficient (BC).
        BC = (skewness^2 + 1) / kurtosis
        Values > 0.555 indicate a bimodal/multimodal distribution,
        characteristic of binary timing channels (Bit 0 vs Bit 1 intervals).
        
        # TR: Sarle Bimodallik Katsayısı:
        # Değer 0.555'ten büyükse veride İKİ AYRI ZİRVE (çift tepe noktası) vardır.
        # Bu durum tam olarak 0 biti (örn: 50ms) ve 1 biti (örn: 150ms) için kullanılan
        # gizli zamanlama kanallarının matematiksel parmak izidir.
        """
        n = len(delays)
        if n < 8:
            return 0.0

        mean = statistics.mean(delays)
        std_dev = statistics.stdev(delays)
        if std_dev == 0:
            return 0.0

        # Skewness (3rd standardized moment)
        skewness = sum(((x - mean) / std_dev) ** 3 for x in delays) * (n / ((n - 1) * (n - 2)))
        
        # Kurtosis (4th standardized moment)
        # Pearson's kurtosis
        kurtosis = (sum(((x - mean) / std_dev) ** 4 for x in delays) / n)
        if kurtosis == 0:
            return 0.0

        bc = (skewness ** 2 + 1.0) / kurtosis
        return round(bc, 4)

    @staticmethod
    def jitter_entropy(delays: List[float], bin_size_ms: float = 10.0) -> float:
        """
        Computes the Shannon entropy of quantized inter-packet delay intervals.
        Quantizes delays into discrete bins and measures uncertainty.
        
        # TR: Gecikme Entropisi: Gecikme sürelerini 10ms'lik sepetlere (bins) ayırıp
        # zamanlama dizisindeki rastgelelik miktarını ölçer.
        """
        if not delays:
            return 0.0

        bins = {}
        for d in delays:
            bin_idx = int(d // bin_size_ms)
            bins[bin_idx] = bins.get(bin_idx, 0) + 1

        total = len(delays)
        entropy = 0.0
        for count in bins.values():
            p = count / total
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    def analyze_stream(self, timestamps: List[float]) -> Dict[str, Any]:
        """
        Performs full spectral and statistical examination of the timestamp sequence.
        
        # TR: Zaman Serisi Analizi: Tüm istatistiksel testleri çalıştırır ve
        # Gizli Zamanlama Kanalı (Covert Timing Channel) olup olmadığını raporlar.
        """
        delays = self.compute_delays(timestamps)
        if len(delays) < self.min_samples:
            return {
                "status": "INSUFFICIENT_SAMPLES",
                "sample_count": len(delays),
                "message": f"Requires at least {self.min_samples} intervals for statistical confidence."
            }

        moments = self.compute_moments(delays)
        bc = self.bimodality_coefficient(delays)
        j_entropy = self.jitter_entropy(delays)

        # Cluster identification for bimodal distribution
        median = statistics.median(delays)
        low_cluster = [d for d in delays if d < median]
        high_cluster = [d for d in delays if d > median]

        has_bimodal_separation = False
        t0_estimate = 0.0
        t1_estimate = 0.0

        if low_cluster and high_cluster:
            t0_estimate = round(statistics.mean(low_cluster), 1)
            t1_estimate = round(statistics.mean(high_cluster), 1)
            # If the two cluster centers are separated by more than 2x their standard deviations
            if (t1_estimate - t0_estimate) > 20.0 and bc > 0.55:
                has_bimodal_separation = True

        indicators = []
        threat_score = 0
        verdict = "BENIGN_NATURAL_TRAFFIC"

        if has_bimodal_separation and bc >= 0.555:
            verdict = "COVERT_TIMING_CHANNEL_DETECTED"
            threat_score = 92
            indicators.append(
                f"Sarle's Bimodality Coefficient {bc:.3f} > 0.555 (Critical dual-state clustering)"
            )
            indicators.append(
                f"Isolated dual delay centers: T0 ~ {t0_estimate}ms, T1 ~ {t1_estimate}ms"
            )
            indicators.append(
                f"Jitter entropy {j_entropy:.3f} bits matches binary code modulation"
            )
        elif moments["cv"] < 0.05 and moments["std_dev"] < 5.0:
            verdict = "SYNTHETIC_PERIODIC_BEACON"
            threat_score = 50
            indicators.append(
                f"Ultra-low timing variance (std_dev={moments['std_dev']}ms, CV={moments['cv']}) - C2 Heartbeat"
            )
        else:
            verdict = "BENIGN_NATURAL_JITTER"
            threat_score = 10
            indicators.append(
                f"Natural unimodal distribution with standard network jitter (CV={moments['cv']})"
            )

        return {
            "sample_count": len(delays),
            "moments": moments,
            "bimodality_coefficient": bc,
            "jitter_entropy": j_entropy,
            "bimodal_detected": has_bimodal_separation,
            "estimated_t0_ms": t0_estimate if has_bimodal_separation else None,
            "estimated_t1_ms": t1_estimate if has_bimodal_separation else None,
            "threat_score": threat_score,
            "verdict": verdict,
            "indicators": indicators,
        }

    @staticmethod
    def decode_covert_bits(delays: List[float], threshold_ms: float) -> str:
        """
        Reconstructs binary bitstream from delays based on threshold,
        and converts 8-bit ASCII chunks into recovered covert message.
        
        # TR: Zamanlama Kanalından Veri Çözme:
        # Eğer gecikme eşik değerinden küçükse 0, büyükse 1 biti olarak çözümlenir.
        # Ardından 8'er bitlik ASCII karakterlere dönüştürülür.
        """
        bits = "".join("0" if d < threshold_ms else "1" for d in delays)
        
        # Convert bitstring to ASCII text
        chars = []
        for i in range(0, len(bits) - 7, 8):
            byte_chunk = bits[i:i + 8]
            val = int(byte_chunk, 2)
            if 32 <= val <= 126:
                chars.append(chr(val))
            else:
                chars.append(".")
        
        return "".join(chars)
