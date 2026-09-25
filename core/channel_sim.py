"""
SpectralCovert - Academic Covert Channel Traffic Simulator & Generator
Author: Çınar (prox0959)
License: MIT

Zero external dependencies. Generates synthetic benign, covert storage,
and covert timing channel streams for research and verification.
"""

import os
import random
import time
from typing import List, Tuple, Dict, Any
from core.entropy import WIN_ICMP_BASELINE


class CovertChannelSimulator:
    """
    Simulates network traffic streams under controlled research conditions
    for evaluating covert channel detection accuracy.
    
    # TR: Gizli Kanal Simülatörü:
    # Akademik araştırmalar ve testler için meşru trafik, gizli depolama (storage) kanalı
    # ve gizli zamanlama (timing) kanalı veri setleri üretir.
    """

    @staticmethod
    def generate_benign_icmp_payloads(count: int = 20) -> List[bytes]:
        """
        Generates benign ICMP payloads matching standard operating system baselines.
        
        # TR: Meşru Windows ve Linux ping paketleri üretir.
        """
        payloads = []
        for _ in range(count):
            # Mix of Windows standard ping and zero-padded buffers
            if random.random() < 0.8:
                payloads.append(WIN_ICMP_BASELINE)
            else:
                payloads.append(b"\x00" * 32)
        return payloads

    @staticmethod
    def generate_covert_storage_payloads(secret_data: bytes, chunk_size: int = 32) -> List[bytes]:
        """
        Fragments a secret (such as high-entropy AES ciphertext or stolen credentials)
        into covert ICMP payload chunks.
        
        # TR: Gizli Depolama Kanalı:
        # Gizli veya şifreli veriyi ICMP ping paketlerinin içerisine gömer.
        """
        # If secret is short, pad with pseudo-random high entropy bytes
        chunks = []
        for i in range(0, len(secret_data), chunk_size):
            chunk = secret_data[i:i + chunk_size]
            if len(chunk) < chunk_size:
                # Pad with pseudo-random bytes to simulate encrypted exfiltration
                chunk += os.urandom(chunk_size - len(chunk))
            chunks.append(chunk)

        # Ensure at least 10 chunks for realistic multi-packet exfiltration
        while len(chunks) < 10:
            chunks.append(os.urandom(chunk_size))

        return chunks

    @staticmethod
    def generate_benign_timestamps(count: int = 50, base_interval_ms: float = 500.0, jitter_std_ms: float = 6.0) -> List[float]:
        """
        Generates benign packet arrival timestamps following Gaussian jitter around a fixed interval.
        
        # TR: Meşru Trafik Zaman Damgaları:
        # Normal bir ping komutunun (örn: 500ms aralıklı) küçük ağ gecikmeleriyle (jitter)
        # tek tepeli (unimodal) varış zamanlarını simüle eder.
        """
        current_time = 1000.0  # arbitrary starting epoch
        timestamps = [current_time]

        for _ in range(count - 1):
            jitter = random.gauss(0, jitter_std_ms)
            interval_sec = max(0.010, (base_interval_ms + jitter) / 1000.0)
            current_time += interval_sec
            timestamps.append(round(current_time, 6))

        return timestamps

    @staticmethod
    def generate_covert_timing_timestamps(
        secret_message: str,
        t0_ms: float = 40.0,
        t1_ms: float = 140.0,
        jitter_std_ms: float = 4.0
    ) -> Tuple[List[float], str]:
        """
        Modulates ASCII message bits into Inter-Packet Delays.
        Bit '0' -> delay t0 + N(0, sigma^2)
        Bit '1' -> delay t1 + N(0, sigma^2)
        
        # TR: Gizli Zamanlama Kanalı:
        # Mesajın her bir bitini (0 ve 1) iki farklı gecikme süresine (40ms ve 140ms) kodlar.
        # Ağdaki rastgele gecikmeler (jitter) eklenerek gerçekçi bimodal dağılım oluşturur.
        """
        # Convert secret message to binary string
        binary_str = "".join(f"{ord(c):08b}" for c in secret_message)

        current_time = 1000.0
        timestamps = [current_time]

        for bit in binary_str:
            target_ms = t0_ms if bit == "0" else t1_ms
            jitter = random.gauss(0, jitter_std_ms)
            interval_sec = max(0.005, (target_ms + jitter) / 1000.0)
            current_time += interval_sec
            timestamps.append(round(current_time, 6))

        return timestamps, binary_str
