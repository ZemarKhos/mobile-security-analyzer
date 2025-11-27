# MobAI - Mobil Güvenlik Analizörü

Gelişmiş Android APK ve iOS IPA güvenlik analiz aracı - Zengin DAST/Frida yetenekleri ile MobSF alternatifi.

![Versiyon](https://img.shields.io/badge/versiyon-2.1.0-blue)
![Platform](https://img.shields.io/badge/platform-Android%20%7C%20iOS-green)
![Lisans](https://img.shields.io/badge/lisans-MIT-orange)

## Hızlı Başlangıç

```bash
# Projeyi klonla
git clone https://github.com/UmutBarisBASAK/mobile-security-analyzer.git
cd mobile-security-analyzer

# Bootstrap ile kurulum aracını hazırla
./scripts/bootstrap.sh

# Interaktif kurulum
./mobai install

# Servisleri başlat
./mobai start
```

## Özellikler

### Platform Desteği
- **Android APK**: Tam decompilation ve kapsamlı analiz
- **iOS IPA**: Binary analizi ve güvenlik taraması

### Statik Analiz (SAST)
- **Kod Analizi**: SQL injection, hardcoded secret'lar, zayıf kriptografi ve 20+ güvenlik deseni
- **Manifest Analizi**: İzinler, bileşenler, export edilmiş servisler ve güvenlik yapılandırmaları
- **Sertifika Analizi**: Debug sertifikası, süresi dolmuş sertifika ve self-signed kontrolleri
- **Binary Analizi**: Native kütüphaneler, DEX dosyaları ve binary korumaları
- **Risk Puanlama**: 0-100 ağırlıklı risk skoru hesaplama

### Root/Jailbreak & SSL Pinning Tespiti
- **Root Tespiti**: KernelSU, Magisk, SafetyNet, RootBeer dahil 40+ desen
- **SSL Pinning**: OkHttp, Retrofit, TrustManager, Network Security Config
- **Anti-Tampering**: İmza doğrulama, bütünlük kontrolleri
- **iOS Jailbreak**: Cydia, Substrate, yaygın jailbreak yolları
- **iOS SSL**: NSURLSession, ATS, özel güven değerlendirmesi

### Dinamik Analiz (DAST) & Frida Entegrasyonu
- **15 Hazır Frida Şablonu** - 8 bypass kategorisini kapsayan
- **Ultimate Bypass Script**: Ağır korumalı uygulamalar için TÜM teknikleri birleştirir
- **30+ SSL Pinning Kütüphane Desteği**: OkHttp, Trustkit, Conscrypt, Cronet, Cordova ve daha fazlası
- **Native-Level Bypass**: libc.so hook'ları (fopen, access, system, stat, strstr)
- **Flutter SSL Bypass**: libflutter.so pattern matching
- **Emulator Tespiti Bypass**: Build properties, TelephonyManager spoofing
- **HTTP Trafik Yakalama**: OkHttp3, HttpURLConnection'dan request/response yakalama

### Ek Özellikler
- **JWT Kimlik Doğrulama**: Rol tabanlı erişim kontrolü (admin, analyst, viewer)
- **PDF/CSV Export**: Kapsamlı güvenlik raporları
- **CVE Eşleştirme**: Bulguları bilinen güvenlik açıklarıyla eşleştirme
- **Rapor Karşılaştırma**: Uygulama versiyonları arasında güvenlik durumu karşılaştırması
- **AI Entegrasyonu**: Gelişmiş analiz için OpenAI, Claude, Gemini, Ollama
- **Özel Güvenlik Kuralları**: Web UI üzerinden tespit desenlerini ekleme/düzenleme
- **Karanlık Mod**: Sistem uyumlu tema ve manuel geçiş

## Kurulum

### Otomatik Kurulum (Önerilen)

```bash
# Bootstrap scriptini çalıştır
./scripts/bootstrap.sh

# Interaktif kurulum
./mobai install

# Veya doğrudan tam kurulum
./mobai install --full
```

### MobAI CLI Komutları

```bash
# Kurulum
./mobai install              # Interaktif tam kurulum
./mobai install --backend    # Sadece backend
./mobai install --frontend   # Sadece frontend
./mobai install --docker     # Docker ile kurulum
./mobai install --dev        # Geliştirici modu

# Servis Yönetimi
./mobai start                # Servisleri başlat
./mobai stop                 # Servisleri durdur
./mobai restart              # Yeniden başlat
./mobai status               # Durum göster

# Sistem
./mobai health               # Sağlık kontrolü
./mobai check                # Gereksinim kontrolü
./mobai logs -f              # Canlı log takibi

# Veritabanı
./mobai db backup            # Yedekle
./mobai db restore <dosya>   # Geri yükle
./mobai db reset             # Sıfırla

# Opsiyonel Araçlar
./mobai tools list           # Kurulu araçları listele
./mobai tools install        # Araç kur (frida, adb, jadx, objection, r2)

# Güncelleme & Kaldırma
./mobai update               # Güncelle
./mobai uninstall            # Kaldır
```

### Docker ile Kurulum

```bash
# Docker compose ile başlat
docker-compose up -d

# Tarayıcıda aç
open http://localhost:3000
```

### Manuel Kurulum

#### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

#### Frontend
```bash
cd frontend
npm install
npm run dev
```

## Kullanım

### Temel Analiz
1. Ana sayfada "APK/IPA Yükle" butonuna tıklayın
2. APK/IPA dosyanızı sürükleyip bırakın veya seçin
3. Analiz otomatik olarak başlar
4. Tamamlandığında kapsamlı güvenlik dashboard'unu görüntüleyin

### DAST / Frida Script Üretimi

#### Hızlı Başlangıç - Hazır Scriptler
```bash
# Ultimate bypass al (tüm teknikler)
curl http://localhost:8000/api/dast/ultimate/android

# Belirli bypass türü al
curl "http://localhost:8000/api/dast/quickstart/android?bypass_type=ssl"
curl "http://localhost:8000/api/dast/quickstart/android?bypass_type=root"
curl "http://localhost:8000/api/dast/quickstart/android?bypass_type=flutter"
curl "http://localhost:8000/api/dast/quickstart/android?bypass_type=mega"
```

#### Analiz Sonuçlarından Üret
```bash
# Tespit edilen korumalara göre otomatik üret
curl -X POST "http://localhost:8000/api/dast/generate/1"

# Ultimate mod - tüm bypass'lar
curl -X POST "http://localhost:8000/api/dast/generate/1?mode=ultimate"

# Trafik yakalama ve native bypass ile
curl -X POST "http://localhost:8000/api/dast/generate/1?include_traffic_intercept=true&include_native_bypass=true"
```

#### Üretilen Scriptleri Kullanma
```bash
# Script'i dosyaya kaydet
curl http://localhost:8000/api/dast/ultimate/android | jq -r '.script' > bypass.js

# Frida ile çalıştır
frida -U -f com.target.app -l bypass.js --no-pause
```

### Güvenlik Kuralları Yönetimi
1. "Güvenlik Kuralları" sayfasına gidin
2. 47 varsayılan kuralı yüklemek için "Varsayılanları Yükle" butonuna tıklayın
3. "Kural Ekle" butonu ile özel kurallar ekleyin
4. Mevcut kuralları düzenleyin, devre dışı bırakın veya silin

### AI Destekli Analiz
1. Bir raporu açın ve "AI Analizi" sekmesine gidin
2. "AI Ayarları"nda AI sağlayıcısını yapılandırın
3. AI destekli bypass scriptleri için "Frida Script Üret" butonuna tıklayın

## API Endpoint'leri

### Raporlar
| Metod | Endpoint | Açıklama |
|-------|----------|----------|
| GET | `/api/reports` | Tüm raporları listele |
| GET | `/api/reports/{id}` | Rapor detaylarını al |
| DELETE | `/api/reports/{id}` | Raporu sil |
| GET | `/api/reports/{id}/findings` | Sayfalanmış bulguları al |
| POST | `/api/reports/compare` | İki raporu karşılaştır |

### Yükleme & Analiz
| Metod | Endpoint | Açıklama |
|-------|----------|----------|
| POST | `/api/upload` | Analiz için APK/IPA yükle |
| GET | `/api/reports/{id}/status` | Analiz durumunu kontrol et |

### DAST & Frida Şablonları
| Metod | Endpoint | Açıklama |
|-------|----------|----------|
| GET | `/api/dast/templates` | Tüm Frida şablonlarını listele |
| GET | `/api/dast/templates/{id}` | Belirli şablonu al |
| GET | `/api/dast/templates/categories/list` | Bypass kategorilerini listele |
| POST | `/api/dast/templates/combine` | Birden fazla şablonu birleştir |
| POST | `/api/dast/generate/{report_id}` | Analizden script üret |
| GET | `/api/dast/ultimate/{platform}` | Ultimate bypass script al |
| GET | `/api/dast/quickstart/{platform}` | Quickstart script al |
| POST | `/api/dast/hooks/generate` | Özel hook üret |
| GET | `/api/dast/trace/crypto/{platform}` | Crypto tracing script al |
| GET | `/api/dast/trace/network/{platform}` | Network tracing script al |

### Kimlik Doğrulama
| Metod | Endpoint | Açıklama |
|-------|----------|----------|
| POST | `/api/auth/login` | Kullanıcı girişi |
| POST | `/api/auth/register` | Kullanıcı kaydı |
| POST | `/api/auth/refresh` | Token yenile |

### Güvenlik Kuralları
| Metod | Endpoint | Açıklama |
|-------|----------|----------|
| GET | `/api/rules` | Tüm kuralları listele |
| POST | `/api/rules` | Yeni kural oluştur |
| PUT | `/api/rules/{id}` | Kuralı güncelle |
| DELETE | `/api/rules/{id}` | Kuralı sil |
| POST | `/api/rules/seed` | Varsayılan kuralları yükle |

### CVE & Export
| Metod | Endpoint | Açıklama |
|-------|----------|----------|
| GET | `/api/cve/report/{id}` | Rapor için CVE eşleşmelerini al |
| GET | `/api/export/{id}/pdf` | Raporu PDF olarak dışa aktar |
| GET | `/api/export/{id}/csv` | Bulguları CSV olarak dışa aktar |

## Frida Şablon Kategorileri

| Kategori | Şablon Sayısı | Açıklama |
|----------|---------------|----------|
| `root_detection` | 4 | Root/SU bypass (KernelSU, Magisk, RootBeer) |
| `ssl_pinning` | 4 | SSL sertifika pinning (30+ kütüphane) |
| `emulator_detection` | 1 | Emulator tespiti bypass |
| `anti_debug` | 1 | Anti-debugging/Anti-Frida |
| `jailbreak_detection` | 2 | iOS jailbreak tespiti |
| `flutter_bypass` | 1 | Flutter'a özel SSL bypass |
| `traffic_interception` | 1 | HTTP/HTTPS trafik yakalama |

### Desteklenen SSL Kütüphaneleri (MEGA Bypass)
- TrustManager (Android < 7 ve > 7)
- OkHTTP v3 (dörtlü bypass metodu)
- Trustkit (üçlü bypass)
- Appcelerator Titanium
- Fabric / Twitter SDK
- IBM MobileFirst / WorkLight
- Conscrypt CertPinManager
- CWAC-Netsecurity
- Netty FingerprintTrustManagerFactory
- Squareup OkHTTP (legacy)
- Apache Cordova
- PhoneGap
- Boye AbstractVerifier
- Appmattus CertificateTransparency
- Chromium Cronet
- Flutter HttpCertificatePinning
- **Dinamik SSLPeerUnverifiedException Otomatik Patcher**

## Teknoloji Yığını

### Backend
- Python 3.11+
- FastAPI
- SQLite (aiosqlite)
- Pydantic v2
- APKTool (APK decompilation)

### Frontend
- React 18 (Vite)
- TypeScript
- Tailwind CSS
- Lucide Icons

### Altyapı
- Docker & Docker Compose
- Nginx reverse proxy
- Systemd servisleri

## Sistem Gereksinimleri

### Gerekli
- Python 3.8+
- Node.js 18+
- Java JDK 11+ (APKTool için)
- Git

### Opsiyonel
- Docker (konteyner deployment için)
- APKTool (APK decompilation için)
- Frida (DAST için)
- ADB (cihaz bağlantısı için)

### Opsiyonel Araçlar
```bash
# Araçları listele
./mobai tools list

# Araç kur
./mobai tools install frida     # Frida araçları
./mobai tools install adb       # Android Debug Bridge
./mobai tools install jadx      # Java decompiler
./mobai tools install objection # Frida tabanlı güvenlik aracı
./mobai tools install r2        # Radare2 reverse engineering
```

## Geliştirme

### Özel Güvenlik Desenleri Ekleme

API üzerinden:
```bash
curl -X POST http://localhost:8000/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Özel Root Kontrolü",
    "type": "root_detection",
    "category": "custom_checks",
    "pattern": "isRooted|checkRoot",
    "is_regex": true,
    "description": "Özel root tespit deseni",
    "severity": "high",
    "bypass_difficulty": "medium",
    "platform": "android"
  }'
```

### Yeni Frida Şablonları Ekleme

`backend/frida_templates.py` dosyasını düzenleyin:
```python
FRIDA_TEMPLATES["my_custom_bypass"] = FridaTemplate(
    id="my_custom_bypass",
    name="Özel Bypass",
    category=BypassCategory.ROOT_DETECTION,
    platform="android",
    description="Bu bypass'ın ne yaptığının açıklaması",
    targets=["com.example.Class"],
    script=MY_CUSTOM_SCRIPT,
    difficulty="medium"
)
```

## Yapılandırma

### Environment Değişkenleri

`config/.env.example` dosyasını `.env` olarak kopyalayın:

```bash
cp config/.env.example .env
```

Önemli yapılandırmalar:
- `JWT_SECRET_KEY`: JWT imzalama anahtarı (güvenli bir anahtar oluşturun)
- `DATABASE_PATH`: SQLite veritabanı yolu
- `UPLOAD_DIR`: Yüklenen dosyaların dizini
- `AI_PROVIDER`: AI sağlayıcısı (openai, anthropic, google, ollama)
- `AI_API_KEY`: AI API anahtarı

## Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/harika-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Harika özellik ekle'`)
4. Branch'i push edin (`git push origin feature/harika-ozellik`)
5. Pull Request açın

## Lisans

MIT Lisansı - detaylar için [LICENSE](LICENSE) dosyasına bakın.

## Teşekkürler

- [Frida](https://frida.re/) - Dinamik enstrümantasyon toolkit'i
- [APKTool](https://ibotpeaches.github.io/Apktool/) - APK reverse engineering
- [Androguard](https://github.com/androguard/androguard) - Android analizi

---

## Dosya Yapısı

```
mobile-security-analyzer/
├── mobai                    # Ana çalıştırılabilir CLI
├── install.py               # Python kurulum scripti
├── scripts/
│   └── bootstrap.sh         # Bootstrap scripti
├── config/
│   ├── .env.example         # Environment şablonu
│   └── systemd/             # Systemd servis dosyaları
├── backend/
│   ├── main.py              # FastAPI uygulaması
│   ├── frida_templates.py   # Frida şablonları
│   └── requirements.txt     # Python bağımlılıkları
├── frontend/
│   ├── src/                 # React kaynak kodları
│   └── package.json         # Node.js bağımlılıkları
├── data/                    # Veritabanı dizini
├── uploads/                 # Yüklenen dosyalar
└── logs/                    # Log dosyaları
```
