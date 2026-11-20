# 🕷️ STYX-RECON

**Hafif DNS keşif ve isteğe bağlı TLS sertifika inceleme aracı.**

[English documentation](README_EN.md)

STYX-RECON; güvenlik araştırması, OSINT ve ağ envanteri için tasarlanmış hafif bir Python aracıdır. Herkese açık DNS kayıtlarını toplar ve isteğe bağlı olarak hedefin TLS sertifikasını inceler. Sonuçlar okunabilir bir terminal tablosu veya JSON olarak sunulur.

<p>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-14B8A6.svg" />
  <a href="https://github.com/raxwqx/STYX-RECON/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/raxwqx/STYX-RECON/actions/workflows/tests.yml/badge.svg?branch=main" /></a>
</p>

## ✨ Özellikler

- 🔎 A, AAAA, MX, NS, TXT ve CNAME kayıtları
- 🔐 **İsteğe bağlı TLS sertifika incelemesi (`--tls`)** — yeni
- 🧾 JSON çıktısı (araç/sürüm bilgisi, DNS kayıtları, uyarılar ve isteğe bağlı TLS sonucu)
- ⏱️ DNS ve TLS için yapılandırılabilir zaman aşımı
- ⚠️ Sessizce yutulmayan çözümleyici hataları: NXDOMAIN, zaman aşımı ve ad sunucusu hataları uyarı olarak raporlanır
- ✅ Hedef doğrulama ve normalleştirme (URL, boşluk, kontrol karakteri ve geçersiz etiket reddi)
- 🌍 Uluslararası alan adları için punycode dönüşümü
- 🧼 Terminal çıktısında kontrol karakteri temizliği ve Rich markup etkisizleştirme
- 📊 Rich tabanlı okunabilir çıktı
- 🚦 Betikler için anlamlı çıkış kodları
- 🧪 Ağ erişimi gerektirmeyen birim testleri
- 🐍 Python 3.10+ ve hafif bağımlılıklar

## 📦 Gereksinimler

- Python 3.10 veya üzeri
- `dnspython` ve `rich`
- DNS sorguları için sistem çözümleyicisine erişim
- TLS incelemesi için hedefin seçilen portuna (varsayılan 443) TCP erişimi

## 🚀 Kurulum

Depoyu klonlayın:

```bash
git clone https://github.com/raxwqx/STYX-RECON.git
cd STYX-RECON
```

Sanal ortam oluşturup paketi kurun:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Windows'ta etkinleştirme komutu:

```powershell
.venv\Scripts\activate
```

Alternatif olarak yalnızca bağımlılıkları kurup modül olarak çalıştırabilirsiniz:

```bash
pip install -r requirements.txt
python -m styxrecon example.com
```

## ⚡ Kullanım

```bash
styx-recon example.com
```

Modül olarak:

```bash
python -m styxrecon example.com
```

JSON çıktısı:

```bash
styx-recon example.com --json
```

TLS sertifika incelemesi:

```bash
styx-recon example.com --tls
```

Farklı TLS portu ve zaman aşımı:

```bash
styx-recon example.com --tls --port 8443 --timeout 10
```

Yardım ve sürüm:

```bash
styx-recon --help
styx-recon --version
```

> `--port` yalnızca `--tls` ile birlikte kullanılabilir. Varsayılan port 443'tür.

## 🖥️ Örnek çıktı

```text
🕷️ STYX-RECON
Target: example.com

              DNS Reconnaissance
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Record ┃ Value                            ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ A      │ 192.0.2.10                       │
│ A      │ 192.0.2.11                       │
│ AAAA   │ 2001:db8::10                     │
│ MX     │ 10 mail.example.com.             │
│ NS     │ ns1.example.com.                 │
│ NS     │ ns2.example.com.                 │
│ TXT    │ "v=spf1 -all"                    │
│ CNAME  │ -                                │
└────────┴──────────────────────────────────┘
```

`--tls` eklendiğinde sertifika tablosu da gösterilir:

```text
                                TLS Certificate
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field          ┃ Value                                           ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Host           │ example.com:443                                 │
│ Verified       │ yes                                             │
│ Protocol       │ TLSv1.3                                         │
│ Cipher         │ TLS_AES_256_GCM_SHA384                          │
│ Subject        │ commonName=example.com                          │
│ Issuer         │ commonName=Example CA                           │
│ Serial         │ 01AB...                                         │
│ Not before     │ 2026-01-01T00:00:00+00:00                       │
│ Not after      │ 2027-01-01T00:00:00+00:00                       │
│ Days remaining │ 214                                             │
│ Expired        │ no                                              │
│ SAN            │ DNS:example.com, DNS:www.example.com            │
└────────────────┴─────────────────────────────────────────────────┘
```

## 🔐 TLS incelemesi

TLS kontrolü yalnızca `--tls` verildiğinde ve hedef mevcut olduğunda yapılır. Araç önce sistem güven deposunu kullanan **doğrulanmış** bir el sıkışma dener. Sertifika süresi dolmuş, kendinden imzalı veya ana makine adı uyuşmuyorsa inceleme doğrulamasız bir el sıkışmayla tekrarlanır; böylece sertifika ayrıntıları yine de gösterilir ancak `Verified: no` ve bir doğrulama uyarısı yer alır.

Raporlanan alanlar:

- Bağlantı durumu ve doğrulama sonucu
- TLS protokolü ve şifreleme paketi
- Subject ve issuer
- Seri numarası
- Geçerlilik başlangıç/bitiş zamanı (UTC, ISO 8601)
- Kalan gün sayısı ve süre dolumu bilgisi
- Subject Alternative Name (SAN) girdileri

TLS incelemesi tek bir port üzerinde tek bir el sıkışma yapar; port taraması veya sertifika zinciri analizi yapmaz.

## 🔍 DNS kayıtları

| Kayıt | Açıklama |
| ----- | -------- |
| A | IPv4 adresi |
| AAAA | IPv6 adresi |
| MX | Posta sunucuları (öncelik dahil) |
| NS | Yetkili ad sunucuları |
| TXT | Metin kayıtları |
| CNAME | Kanonik ad |

Kayıt değerleri tekilleştirilir ve deterministik çıktı için sıralanır. Bir kayıt türü yoksa tabloda `-` gösterilir.

## 📦 JSON çıktısı

```bash
styx-recon example.com --json
```

Örnek:

```json
{
  "tool": "styx-recon",
  "version": "0.2.0",
  "target": "example.com",
  "exists": true,
  "resolved": true,
  "dns": {
    "A": ["192.0.2.10"],
    "AAAA": ["2001:db8::10"],
    "MX": ["10 mail.example.com."],
    "NS": ["ns1.example.com."],
    "TXT": ["\"v=spf1 -all\""],
    "CNAME": []
  },
  "warnings": [],
  "tls": {
    "hostname": "example.com",
    "port": 443,
    "connected": true,
    "verified": true,
    "error": null,
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "subject": "commonName=example.com",
    "issuer": "commonName=Example CA",
    "serial_number": "01AB...",
    "not_before": "2026-01-01T00:00:00+00:00",
    "not_after": "2027-01-01T00:00:00+00:00",
    "days_remaining": 214,
    "expired": false,
    "san": ["DNS:example.com", "DNS:www.example.com"]
  }
}
```

Notlar:

- `tls` yalnızca `--tls` kullanıldığında bulunur.
- `warnings` her zaman dizidir; boş olabilir.
- `exists`, hedefin NXDOMAIN olup olmadığını; `resolved`, en az bir kayıt yanıtı alınıp alınmadığını gösterir.
- DNS değerleri JSON'da ham hâliyle korunur; terminalde kontrol karakterleri temizlenir.

## 🚦 Çıkış kodları

| Kod | Anlam |
| --- | ----- |
| `0` | Sorgu tamamlandı ve en az bir DNS yanıtı alındı; TLS istendiyse bağlantı kuruldu |
| `1` | Hedef yok (NXDOMAIN), DNS yanıtı alınamadı veya istenen TLS bağlantısı kurulamadı |
| `2` | Geçersiz hedef, port, zaman aşımı veya komut satırı kullanımı |

## 🛡️ Hedef doğrulama ve sınırlar

- Hedef en fazla 253 karakter, her etiket en fazla 63 karakter olabilir.
- Tek bir sondaki nokta kabul edilir ve kaldırılır; tekrarlanan sondaki noktalar reddedilir.
- URL, boşluk, kontrol karakteri, boş etiket ve baştaki/sondaki tire içeren hedefler reddedilir.
- ASCII olmayan alan adları punycode'a çevrilir (ör. `bücher.example` → `xn--bcher-kva.example`).
- `--timeout` 0'dan büyük ve en fazla 60 saniye olabilir.
- TLS portu 1–65535 aralığındadır.
- NXDOMAIN alındığında kalan kayıt türleri sorgulanmaz.
- Ad sunucusu hatası veya zaman aşımında kalan sorgular durdurulur ve tek bir uyarı gösterilir.
- Tek bir kayıt türü başarısız olursa diğer türler sorgulanmaya devam eder.

## 🧪 Testler

Testler ağ erişimi gerektirmez; DNS ve TLS katmanları taklit edilerek doğrulanır.

```bash
pip install -e ".[dev]"
python -m pytest -q
```

CI; Linux, macOS ve Windows üzerinde Python 3.10–3.13 sürümleriyle derleme, test ve CLI sürüm kontrolü çalıştırır.

## 📁 Proje yapısı

```text
STYX-RECON/
├── styxrecon/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── dns.py
│   ├── reporter.py
│   ├── tls.py
│   └── whois.py
├── tests/
│   ├── test_cli.py
│   ├── test_dns.py
│   └── test_tls.py
├── .github/workflows/tests.yml
├── CHANGELOG.md
├── README.md
├── README_EN.md
├── pyproject.toml
└── requirements.txt
```

## 🗺️ Yol haritası

- WHOIS sorguları
- DNS over HTTPS desteği
- SPF/DMARC/CAA güvenlik özeti
- CSV ve HTML raporlama
- Daha kapsamlı sertifika zinciri analizi

## ⚠️ Sorumluluk reddi

STYX-RECON yalnızca **eğitim, güvenlik araştırması ve yetkili test** amacıyla kullanılmalıdır. Yetkiniz olmayan sistemlere veya alan adlarına karşı kullanmayın. Geliştirici, kötüye kullanımdan veya oluşabilecek zarardan sorumlu değildir.

## 📜 Lisans

MIT
