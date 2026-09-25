# 📡 SpectralCovert

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-0%20(Pure%20Stdlib)-brightgreen.svg)]()
[![Detection: Mathematical](https://img.shields.io/badge/engine-Shannon%20Entropy%20%7C%20Sarle's%20BC-orange.svg)]()
[![Platform: Cross-Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

> **Deterministic Cryptographic Network Covert Channel & Shannon Entropy Leak Detector**  
> Developed by **Çınar ([@prox0959](https://github.com/prox0959))**  
> *Academic Grade | Zero External Dependencies | Sub-Millisecond Analysis*

---

## 🔬 Overview & Problem Statement

Modern firewalls, deep packet inspection (DPI) engines, and data loss prevention (DLP) systems examine packet headers and search for cleartext patterns. Advanced Persistent Threats (APTs) and sophisticated malware evade these perimeters using **Covert Channels** (defined under DoD 5200.28-STD and academic information flow control):

1. **Covert Storage Channels (RFC 792 / RFC 791):** Smuggling encrypted data (AES / ChaCha20) or exfiltration tokens inside legitimate protocol padding fields (e.g., ICMP Echo Request payloads, TCP urgent pointers, IP identification fields).
2. **Covert Timing Channels (CTC):** Never modifying packet bytes at all! Instead, transmitting binary data by modulating the **Inter-Packet Delay (IPD)** between consecutive packets ($T_0$ for bit `0`, $T_1$ for bit `1`). The payload is 100% benign, but the *rhythm* leaks confidential data.

**SpectralCovert** detects both vectors using pure mathematical statistics: **Shannon Information Entropy**, **Sarle's Bimodality Coefficient**, and **Jitter Spectral Analysis** with zero external dependencies.

---

## 📐 Mathematical Foundations

### 1. Shannon Information Entropy ($H$)
Information entropy quantifies the degree of uncertainty or compressibility in a byte sequence:

$$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

- **Theoretical Maximum:** $8.0 \text{ bits/byte}$ for 256 byte values.
- **Sample Length Normalization:** For a packet of length $N$, the absolute maximum entropy cannot exceed $\log_2(N)$ bits. SpectralCovert calculates sample-length normalized entropy:

$$H_{norm} = \frac{H(X)}{\min(8.0, \log_2(N))}$$

- **Detection Thresholds:**
  - $H_{norm} \ge 0.90$ with Unique Byte Ratio $\ge 80\%$: High-confidence encrypted exfiltration (AES/ChaCha20).
  - $H_{norm} < 0.85$: Natural language, structured protocol headers, or benign OS ping baselines.

### 2. Sarle's Bimodality Coefficient ($BC$) for Covert Timing Channels
When an adversary modulates bits $0$ and $1$ across inter-packet arrival times ($\Delta t_i = t_i - t_{i-1}$), natural network jitter converts the discrete delays into a **bimodal Gaussian mixture distribution**.

$$BC = \frac{\gamma^2 + 1}{\kappa}$$

Where:
- $\gamma$ = Sample Skewness (3rd standardized moment)
- $\kappa$ = Sample Kurtosis (4th standardized moment)
- **Decision Rule:** $BC > 0.555$ indicates a multimodal/bimodal distribution with two distinct cluster peaks ($T_0$ and $T_1$), exposing the hidden binary transmission channel!

---

## ⚡ Key Features

- **Zero External Dependencies:** Built entirely with Python standard library (`socket`, `struct`, `math`, `statistics`, `argparse`, `time`, `random`). No `pip install` required.
- **Dual Vector Detection:**
  - **Storage:** ICMP/TCP payload entropy, byte diversity ratio, and OS baseline matching (Windows `abcdef...`, Linux sequential).
  - **Timing:** Inter-packet delay (IPD) analysis, Sarle's bimodality coefficient, and quantized jitter entropy.
- **Automated Covert Payload Recovery:** Automatically calculates the bimodal separation threshold and reconstructs the modulated ASCII secret from packet arrival delays!
- **Terminal Spectral Visualizer:** Cross-platform ASCII frequency distribution histograms rendered directly in your terminal.
- **Sub-Millisecond Speed:** Instantaneous mathematical verification suitable for inline network taps and edge gateways.

---

## 🚀 Quick Start & CLI Usage

### 1. Run Built-in Academic Benchmark
Runs a complete validation suite testing benign baselines vs encrypted ICMP storage exfiltration and modulated timing channels:

```bash
python spectralcovert.py --demo
```

**Benchmark Output Preview:**
```
========================================================================
      ACADEMIC BENCHMARK: COVERT CHANNEL DETECTION VALIDATION
========================================================================

[PHASE 1] EVALUATING ICMP STORAGE CHANNELS (PAYLOAD SHANNON ENTROPY)
------------------------------------------------------------------------
[*] Test 1: Benign Windows ICMP Echo Request (32 bytes)
    Payload: b'abcdefghijklmnopqrstuvwa'...
    Entropy: [===========---------] 4.438 / 8.000 bits [NORMAL TEXT / OS PING]
    Verdict: BENIGN (Score: 0/100)

[*] Test 2: Covert Exfiltration - Encrypted AES Stolen Key in ICMP Payload
    Payload (hex): 6d379ecb7647003cb5e0b4554c7fb491...
    Entropy: [===========---------] 4.750 / 8.000 bits [NORMAL TEXT / OS PING]
    Verdict: ALERT_COVERT_EXFILTRATION (Score: 95/100)
    -> Near-maximum entropy density (95.0% of theoretical limit, 4.750 bits/byte)
    -> Abnormal byte diversity (87.5% unique symbols) - High confidence encrypted payload

[+] Phase 1 Passed: 100% Accuracy on Storage Exfiltration Channels.

[PHASE 2] EVALUATING COVERT TIMING CHANNELS (IPD & SPECTRAL ANALYSIS)
------------------------------------------------------------------------
[*] Generating benign traffic stream (100 packets, ~200ms interval + jitter)...
    Sample Size: 99 intervals
    Mean Delay: 199.554 ms | StdDev: 5.633 ms
    Sarle's Bimodality Coefficient: 0.3486 (Threshold: 0.555)
    Verdict: BENIGN_NATURAL_JITTER (Threat Score: 10/100)

[*] Generating Covert Timing Channel modulating: 'ETH2026'
    Bit 0 delay -> 40ms, Bit 1 delay -> 140ms + simulated network jitter
    Sarle's Bimodality Coefficient: 1.0282 (Threshold: 0.555)
    Detected Dual Clusters: T0 ~ 38.4 ms | T1 ~ 112.3 ms
    Verdict: COVERT_TIMING_CHANNEL_DETECTED (Threat Score: 92/100)

--- Bimodal Inter-Packet Delay Histogram ---
  32.6 -   46.9 ms | ######################### (33)
  46.9 -   61.2 ms | ##                        (3)
  61.2 -   75.5 ms |                           (0)
  75.5 -   89.7 ms |                           (0)
  89.7 -  104.0 ms |                           (0)
 104.0 -  118.3 ms |                           (0)
 118.3 -  132.6 ms |                           (1)
 132.6 -  146.9 ms | ##############            (19)

[+] Covert Message Reconstruction Attempt:
    Original Secret : 'ETH2026'
    Decoded Payload : 'ETH2026'
    Match Confirmed : True

[+] Phase 2 Passed: 100% Accuracy on Covert Timing Channel Detection.
```

---

### 2. Simulate Covert Timing Channel & Visualize Modulation
Simulate data exfiltration using delay modulation and inspect the real-time bimodal distribution:

```bash
python spectralcovert.py --simulate-leak "CONFIDENTIAL_KEY"
```

### 3. Analyze Arbitrary Payloads
Inspect arbitrary text or hex byte sequences for entropy anomalies:

```bash
python spectralcovert.py --analyze-text "sk-proj-938210384019283019283019283019283"
```

---

## 🏛️ Academic Relevance & University Admissions

Covert channel detection is a premier research domain in computer systems security (e.g., Information Security Group at **ETH Zurich**, Network and System Security at **TU Munich**, and Oxford Cyber Security).

This project demonstrates mastery of:
- **Information Theory:** Discrete random variable entropy, Shannon entropy, and length-normalized metrics.
- **Statistical Signal Processing:** 3rd and 4th standardized moments (Skewness and Kurtosis), Bimodality testing ($BC$), and Inter-Packet Delay modeling.
- **Network Protocol Architectures:** RFC 792 (ICMP), packet framing, jitter distributions, and stealth data exfiltration defenses.

---

## 📂 Project Structure

```
SpectralCovert/
├── core/
│   ├── __init__.py         # Package entry
│   ├── entropy.py          # Shannon & normalized entropy, Chi-Squared test, OS baselines
│   ├── timing.py           # IPD analyzer, Sarle's bimodality coefficient, secret bit recovery
│   ├── channel_sim.py      # Synthetic benign & covert traffic generator
│   └── visualizer.py       # ASCII spectral histogram & terminal formatting
├── tests/
│   └── test_covert.py      # Automated unit test suite
├── spectralcovert.py       # Main CLI & benchmark runner
├── README.md               # Technical documentation & mathematics
├── LICENSE                 # MIT License
└── .gitignore
```

---

## 📜 License & Citation

Released under the **MIT License**. Created by **Çınar ([@prox0959](https://github.com/prox0959))**.

```bibtex
@software{spectralcovert2026,
  author = {prox0959},
  title = {SpectralCovert: Deterministic Network Covert Channel and Shannon Entropy Leak Detector},
  year = {2026},
  url = {https://github.com/prox0959/SpectralCovert}
}
```
