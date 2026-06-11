# phishing-mail-analyzer

**Python:** 3.11+ | **Platform:** Linux/Fedora | **Lisans:** MIT | **GitHub:** [orucreis04/phishing-mail-analyzer](https://github.com/orucreis04/phishing-mail-analyzer)

## Proje Özeti

`phishing-mail-analyzer`, `.eml` formatındaki e-posta dosyalarını statik olarak analiz eden Python 3.11+ uyumlu bir CLI güvenlik aracıdır. E-posta header bilgilerini, gövde içeriğini, URL'leri, HTML göstergelerini ve attachment metadata bilgilerini çıkarır; ardından normalize edilmiş bir phishing risk skoru üretir.

Araç, SOC / Blue Team portföy projesi olarak tasarlanmıştır: modülerdir, test edilebilir yapıdadır, Linux/Fedora ortamlarında rahat çalışır ve güvenli statik analiz yaklaşımını temel alır.

## Özellikler

- Python `email` kütüphanesi ile `.eml` dosyası okuma
- Subject, From, To, Date, Message-ID, Return-Path ve Reply-To alanlarını çıkarma
- From, Return-Path, Reply-To ve Message-ID domain uyuşmazlıklarını analiz etme
- `Authentication-Results` içinden SPF, DKIM ve DMARC sonuçlarını kontrol etme
- Received header zincirini ayrıştırma
- Plain text ve HTML gövdeden URL çıkarma
- Şüpheli URL, URL shortener, IP adresli link, punycode domain ve görünen link/href uyuşmazlığı analizi
- Aciliyet, credential isteği, finansal ifade, tehdit dili ve marka taklidi göstergelerini yakalama
- HTML form, script ve gizli içerik tespiti
- Attachment dosyalarını çalıştırmadan yalnızca metadata seviyesinde analiz etme
- Header, URL, body ve attachment sonuçlarından ağırlıklı final risk skoru üretme
- `reports/` klasörüne timestamp içeren JSON rapor kaydetme
- Terminalde profesyonel ve okunabilir özet rapor üretme
- Renkli terminal çıktısını isteğe bağlı kapatma

## Mimari

Analiz akışı aşamalı ve modüler bir statik analiz pipeline'ı olarak çalışır:

1. `parser.py` `.eml` dosyasını okur ve normalize eder.
2. `header_analyzer.py` gönderici kimliği ve authentication sinyallerini analiz eder.
3. `url_analyzer.py` text ve HTML içinden URL çıkarır ve risk sinyallerini skorlar.
4. `body_analyzer.py` sosyal mühendislik ve HTML tabanlı göstergeleri değerlendirir.
5. `attachment_analyzer.py` attachment metadata risklerini analiz eder.
6. `risk_engine.py` bileşen skorlarını tek final phishing risk skoruna dönüştürür.
7. `report_generator.py` JSON rapor üretir ve terminal özetini render eder.
8. `main.py` tüm akışı profesyonel CLI arayüzüyle sunar.

## Klasör Yapısı

```text
phishing-mail-analyzer/
├── main.py
├── requirements.txt
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── samples/
│   └── sample_phishing.eml
├── reports/
├── phishing_analyzer/
│   ├── __init__.py
│   ├── parser.py
│   ├── header_analyzer.py
│   ├── body_analyzer.py
│   ├── url_analyzer.py
│   ├── attachment_analyzer.py
│   ├── risk_engine.py
│   ├── report_generator.py
│   └── utils.py
```

## Fedora/Linux Kurulumu

Python araçları kurulu değilse:

```bash
sudo dnf install -y python3 python3-pip python3-virtualenv
```

Sanal ortam oluşturup bağımlılıkları kurun:

```bash
cd phishing-mail-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py analyze samples/sample_phishing.eml
```

## Kullanım

CLI iki ana komut sağlar:

```bash
python main.py analyze <email.eml>
python main.py version
```

Bir e-postayı analiz edip `reports/` altında timestamp içeren JSON rapor oluşturmak için:

```bash
python main.py analyze samples/sample_phishing.eml
```

JSON raporu terminale yazdırmak için:

```bash
python main.py analyze samples/sample_phishing.eml --json
```

JSON raporu belirli bir dosya yoluna kaydetmek için:

```bash
python main.py analyze samples/sample_phishing.eml --output reports/report.json
```

Renkli terminal çıktısını kapatmak için:

```bash
python main.py analyze samples/sample_phishing.eml --no-color
```

## Örnek Komutlar

```bash
# CLI yardım çıktısı
python main.py --help

# Analyze komutu yardım çıktısı
python main.py analyze --help

# Güvenli örnek phishing e-postasını analiz et
python main.py analyze samples/sample_phishing.eml

# Raporu sabit bir dosya yoluna kaydet
python main.py analyze samples/sample_phishing.eml --output reports/sample_report.json

# Makine tarafından okunabilir JSON çıktı üret
python main.py analyze samples/sample_phishing.eml --json

# Versiyon bilgisini göster
python main.py version
```

## Örnek Çıktı

Terminal özet raporu örneği:

```text
Phishing Mail Analysis
Subject            Urgent action required: Account suspended - verify now
From               PayPal Security <support@paypal-security.example>
Date               Thu, 11 Jun 2026 13:45:00 +0000
Final risk score   79/100
Risk level         Critical

Analysis Metrics
Header signals       6
URL count            3
Suspicious URL count 3
Attachment count     1

Top Suspicious Indicators
- SPF authentication result is fail
- DKIM authentication result is fail
- DMARC authentication result is fail
- From domain and Return-Path domain do not match
- Suspicious URL signal 'ip_address_host' on 192.0.2.10

Recommendations
- Do not open links or attachments. Report to security team.
```

JSON raporları e-posta metadata bilgilerini, component analiz sonuçlarını, final risk skorunu ve önerileri içerir.

## Risk Skorlama Modeli

Final risk skoru `0-100` arasında normalize edilir ve bileşen skorları şu ağırlıklarla hesaplanır:

- Header analizi: `%30`
- URL analizi: `%35`
- Body analizi: `%20`
- Attachment analizi: `%15`

Risk seviyeleri:

```text
0-24   Low
25-49  Medium
50-74  High
75-100 Critical
```

Final risk seviyesine göre öneriler üretilir:

- Critical: Linkleri veya ekleri açmayın. Güvenlik ekibine raporlayın.
- High: Gönderici kimliğini farklı bir kanal üzerinden doğrulayın.
- Medium: Etkileşime geçmeden önce şüpheli göstergeleri inceleyin.
- Low: Büyük bir phishing göstergesi bulunmadı, yine de dikkatli olun.

## Güvenlik Notları

- Bu araç yalnızca statik analiz yapar.
- Attachment içeriklerini çalıştırmaz.
- Şüpheli URL'lere istek göndermez.
- Credential toplama veya aktif phishing davranışı içermez.
- `samples/sample_phishing.eml` dosyası güvenli ve tamamen sahte bir test örneğidir.
- Örnek dosya bilerek şüpheli header, link, HTML form, hidden text ve attachment metadata içerir; gerçek malware veya çalışan phishing payload içermez.

## Yol Haritası

- Tüm analyzer modülleri için unit test ekleme
- CSV ve SARIF export seçenekleri
- Opsiyonel DNS tabanlı SPF/DMARC zenginleştirme
- SOC iş akışları için IOC çıkarımı
- YARA uyumlu attachment metadata etiketleme
- Yapılandırılabilir scoring profilleri
- Lint ve testler için CI workflow
- Paketlenmiş console entry point

## Sorumluluk Reddi

`phishing-mail-analyzer`, savunma odaklı güvenlik eğitimi, SOC portföy çalışmaları ve dahili Blue Team analiz iş akışları için geliştirilmiştir. Secure email gateway, EDR, sandbox veya tam kapsamlı incident response sürecinin yerine geçmez. Şüpheli e-posta örneklerini her zaman kontrollü bir ortamda inceleyin ve kurumunuzun güvenlik prosedürlerini takip edin.
