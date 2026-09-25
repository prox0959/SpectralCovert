# 📓 Çınar'ın Ders & Mülakat Notu: SpectralCovert

> **Proje:** `SpectralCovert v1.0.0` | **Alan:** Ağ Güvenliği, Kriptografik Gizli Kanallar (Covert Channels) & Bilgi Teorisi  
> **Hedef:** ETH Zürih / TU Münih / Wolsey Hall Oxford Mülakat Hazırlığı  
> **Konum:** `c:\Users\prox\Desktop\proxproje\SpectralCovert`

---

## 🧠 1. Temel Problem: Güvenlik Duvarlarını Atlayan Görünmez Veri Sızıntısı
Geleneksel DLP (Veri Sızıntısı Önleme) ve IDS sistemleri sadece paket başlıklarına ve düz metinlere bakar. Gelişmiş saldırganlar (APT grupları) veriyi yakalanmadan dışarı sızdırmak için **Gizli Kanallar (Covert Channels)** kullanır.

* **Covert Storage Channel (Gizli Depolama):**  
  Standart bir ICMP (Ping) paketinin veri kısmına (payload) şifrelenmiş veri gömmek.
* **Covert Timing Channel (Gizli Zamanlama):**  
  Paket içeriğini **HİÇ DEĞİŞTİRMEDEN**, sadece paketlerin **geliş süreleri (aralıkları)** arasındaki ritimle ikili (0 ve 1) veri göndermek!

---

## 🔬 2. Matematiksel & Sinyal İşleme Kavramları

1. **Shannon Bilgi Entropisi Formülü:**
   $$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   - Verideki belirsizlik ve sıkıştırılamazlık ölçüsüdür.
   - 0.0 bit: Tekdüze veri (örn: `00000000`).
   - 8.0 bit: Tamamen rastgele, sıkıştırılmış veya AES ile şifrelenmiş veri.
2. **Normalize Entropi (Küçük Paketler İçin):**
   $$H_{norm} = \frac{H(X)}{\min(8.0, \log_2(N))}$$
   32 baytlık bir ping paketinde teorik maksimum entropi $\log_2(32) = 5.0$ bitten büyük olamaz. Bu yüzden SpectralCovert boyuttan bağımsız standart bir oran üretir ($H_{norm} \ge 0.90$ ise AES şifreli sızıntı alarmı!).
3. **Sarle Bimodallik Katsayısı (Bimodality Coefficient - BC):**
   $$BC = \frac{\gamma^2 + 1}{\kappa}$$
   *(Burada $\gamma$ çarpıklık/skewness, $\kappa$ basıklık/kurtosis değeridir).*
   - $BC \le 0.555$: Normal ağ trafiği (tek tepeli / doğal Gauss dalgalanması).
   - $BC > 0.555$: GİZLİ ZAMANLAMA KANALI TESPİT EDİLDİ! İki ayrı gecikme havuzu ($T_0$ ve $T_1$) vardır.  
   SpectralCovert bu havuzların ortasını ($T_{thresh} = (T_0 + T_1) / 2$) bularak sızdırılan şifreli mesajı (örn: `ETH2026`) otomatik deşifre eder!

---

## 🎯 3. ETH Zürih / TU Münih Mülakat Sorusu & Çınar'ın Cevabı

**Mülakatçı:** *"Bir saldırgan paket içeriğini hiç değiştirmeden sadece paket gecikmeleriyle (Inter-Packet Delay) veri sızdırıyorsa bunu nasıl tespit edersiniz?"*

> **Çınar'ın Cevabı:**  
> *"Bu bir Covert Timing Channel senaryosudur; paket içeriği standart olduğu için DPI motorları kör kalır.  
> SpectralCovert ile paketler arası varış sürelerini (IPD) zaman serisi olarak inceliyorum. Normal ağ trafiği tek tepeli (unimodal) bir jitter sergilerken, bit modülasyonu yapan saldırganlar iki ayrı gecikme kümesi (T0 ve T1) oluşturur. Sarle'nin Bimodallik Katsayısı (BC) 0.555 eşiğini aştığında çift tepeli dağılımı matematiksel olarak kanıtlayıp sızdırılan bitleri eşik filtreleme yöntemiyle anında deşifre edebiliyoruz."*
