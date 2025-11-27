# Değişiklik Günlüğü

MobAI - Mobil Güvenlik Analizörü için tüm önemli değişiklikler bu dosyada belgelenmektedir.

Format [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)'a dayanmaktadır
ve proje [Semantic Versioning](https://semver.org/spec/v2.0.0.html) kullanmaktadır.

## [2.2.0] - 2025-11-27

### Eklenenler

#### Kapsamlı Kurulum Aracı (MobAI CLI)
- **Interaktif Kurulum**: Rich kütüphanesi ile renkli, zengin terminal arayüzü
- **Çoklu Kurulum Modları**: Tam, backend, frontend, Docker ve geliştirici modları
- **Servis Yönetimi**: start/stop/restart/status komutları ile servis kontrolü
- **Veritabanı Yönetimi**: backup/restore/reset komutları
- **Sistem Sağlık Kontrolü**: Tüm gereksinimlerin otomatik kontrolü
- **Opsiyonel Araç Kurulumu**: frida, adb, jadx, objection, r2 kurulum desteği

#### Yeni Dosyalar
- `mobai` - Ana çalıştırılabilir shell wrapper
- `install.py` - Python kurulum ve yönetim scripti (~1600 satır)
- `scripts/bootstrap.sh` - Bağımlılık kurulum bootstrap scripti
- `requirements-installer.txt` - Installer Python bağımlılıkları
- `config/.env.example` - Kapsamlı environment değişkenleri şablonu
- `config/systemd/mobai-backend.service` - Backend systemd servisi
- `config/systemd/mobai-frontend.service` - Frontend systemd servisi

#### CLI Komutları
```bash
# Kurulum
./mobai install              # Interaktif tam kurulum
./mobai install --backend    # Sadece backend
./mobai install --frontend   # Sadece frontend
./mobai install --docker     # Docker ile kurulum
./mobai install --dev        # Geliştirici modu

# Servis Yönetimi
./mobai start/stop/restart/status

# Sistem
./mobai health               # Sağlık kontrolü
./mobai check                # Gereksinim kontrolü
./mobai logs -f              # Canlı log takibi

# Veritabanı
./mobai db backup/restore/reset

# Araçlar
./mobai tools list/install
```

### Değişenler
- README.md Türkçe'ye çevrildi
- CHANGELOG.md Türkçe'ye çevrildi
- Kurulum süreci basitleştirildi

---

## [2.1.0] - 2025-11-27

### Eklenenler

#### Geliştirilmiş DAST/Frida Yetenekleri
- **6 Yeni Frida Şablonu** - toplam 15 şablon, 8 kategoride
- **Ultimate Bypass Script**: Ağır korumalı uygulamalar için TÜM bypass tekniklerini birleştirir (~41KB)
- **MEGA SSL Pinning Bypass**: 30+ SSL pinning implementasyonunu kapsayan kapsamlı bypass
- **Flutter SSL Bypass**: Native libflutter.so pattern matching bypass
- **Emulator Tespiti Bypass**: Build properties, TelephonyManager ve sensör spoofing
- **Native-Level Bypass**: libc.so hook'ları (fopen, access, system, stat, strstr)
- **HTTP Trafik Yakalama**: OkHttp3, HttpURLConnection ve WebView trafiği yakalama

#### Yeni Root Tespit Özellikleri
- **KernelSU Desteği**: `/data/adb/ksu`, `/data/adb/ksud` tespit yolları
- **40+ Root Yolu**: Modern root çözümlerini kapsayan kapsamlı kapsam
- **16+ Root Yönetim Uygulaması**: `me.weishu.kernelsu` dahil
- **ProcessBuilder Bypass**: ProcessBuilder ile komut çalıştırma hook'u
- **UnixFileSystem Bypass**: Java seviyesi dosya sistemi kontrolü bypass'ı

#### Desteklenen SSL Kütüphaneleri (MEGA Bypass)
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

#### Yeni API Endpoint'leri
- `GET /api/dast/ultimate/{platform}` - TÜM tekniklerle ultimate bypass script al
- `GET /api/dast/quickstart/{platform}?bypass_type=ultimate` - Ultimate bypass'a hızlı erişim
- Geliştirilmiş `POST /api/dast/generate/{report_id}` - `mode` parametresi ile (auto/mega/ultimate)
- Yeni query parametreleri: `include_traffic_intercept`, `include_native_bypass`

#### Yeni Bypass Kategorileri
- `traffic_interception` - HTTP/HTTPS trafik yakalama
- `flutter_bypass` - Flutter'a özel SSL bypass

### Değişenler
- **Root Tespit Şablonu**: Temel seviyeden 40+ yol ile gelişmiş seviyeye yükseltildi
- **Şablon Kaydı**: 10'dan 15 şablona genişletildi
- **Script Üretimi**: Artık çoklu üretim modlarını destekliyor
- **API Dokümantasyonu**: Detaylı endpoint açıklamalarıyla geliştirildi

### İyileştirmeler
- Flutter uygulamalarının daha iyi tespiti ve otomatik Flutter bypass dahil edilmesi
- Tespit edilen güvenlik mekanizmalarına göre daha akıllı şablon seçimi
- Üretilen scriptlerde daha kapsamlı loglama

---

## [2.0.0] - 2025-11-26

### Eklenenler
- **JWT Kimlik Doğrulama**: Rol tabanlı erişim kontrolü (admin, analyst, viewer)
- **PDF Export**: WeasyPrint ile kapsamlı güvenlik raporları
- **CSV Export**: Harici analiz için bulgu dışa aktarımı
- **CVE Veritabanı Entegrasyonu**: Bulguları bilinen güvenlik açıklarıyla eşleştirme
- **Rapor Karşılaştırma**: Uygulama versiyonları arasında güvenlik durumu karşılaştırması
- **DAST API**: İlk Frida script üretim yetenekleri
- **Rate Limiting**: slowapi ile API koruması
- **Denetim Günlüğü**: Kullanıcı işlemlerini ve dosya yüklemelerini izleme

### Değişenler
- Pydantic v2'ye yükseltildi
- Uygulama genelinde hata işleme iyileştirildi
- Yapılandırılmış çıktı ile loglama sistemi geliştirildi

---

## [1.0.0] - 2025-11-25

### Eklenenler
- İlk sürüm
- **Android APK Analizi**: Tam decompilation ve güvenlik taraması
- **iOS IPA Analizi**: Binary analizi ve güvenlik değerlendirmesi
- **Statik Kod Analizi**: 20+ güvenlik deseni tespiti
- **Manifest Analizi**: İzin ve bileşen analizi
- **Sertifika Analizi**: Debug/süresi dolmuş/self-signed tespiti
- **Binary Analizi**: Native kütüphane ve koruma analizi
- **Risk Puanlama**: 0-100 ağırlıklı risk hesaplama
- **Güvenlik Kuralları Motoru**: Özel desen yönetimi
- **AI Entegrasyonu**: OpenAI, Claude, Gemini, Ollama desteği
- **Karanlık Mod**: Sistem uyumlu tema desteği
- **Docker Desteği**: docker-compose ile kolay deployment

---

## Şablon Referansı

### Mevcut Şablonlar (v2.1.0)

| ID | Ad | Kategori | Platform |
|----|-----|----------|----------|
| `android_root_generic` | Gelişmiş Root Tespit Bypass | root_detection | android |
| `android_rootbeer` | RootBeer Kütüphane Bypass | root_detection | android |
| `android_magisk` | Magisk Tespit Bypass | root_detection | android |
| `android_emulator` | Emulator Tespit Bypass | emulator_detection | android |
| `android_native` | Native Level Bypass (libc.so) | root_detection | android |
| `android_ssl_universal` | Evrensel SSL Pinning Bypass | ssl_pinning | android |
| `android_network_security` | Network Security Config Bypass | ssl_pinning | android |
| `android_ssl_mega` | MEGA SSL Pinning Bypass (30+ lib) | ssl_pinning | android |
| `android_flutter_ssl` | Flutter SSL Pinning Bypass | flutter_bypass | android |
| `android_traffic_intercept` | HTTP Trafik Yakalama | traffic_interception | android |
| `android_anti_debug` | Anti-Debug/Anti-Frida Bypass | anti_debug | android |
| `android_master` | Android Master Bypass | root_detection | android |
| `ios_jailbreak` | iOS Jailbreak Tespit Bypass | jailbreak_detection | ios |
| `ios_ssl` | iOS SSL Pinning Bypass | ssl_pinning | ios |
| `ios_master` | iOS Master Bypass | jailbreak_detection | ios |

---

## Geçiş Rehberi

### 2.1.0'dan 2.2.0'a

Kırılma değişikliği yok. Yeni kurulum aracı eklenmiştir.

Yeni kurulum aracını kullanmak için:
```bash
# Bootstrap scriptini çalıştır
./scripts/bootstrap.sh

# Artık mobai CLI kullanılabilir
./mobai --help
./mobai install
./mobai start
```

### 2.0.0'dan 2.1.0'a

Kırılma değişikliği yok. Yeni özellikler eklemedir.

Yeni DAST özelliklerini kullanmak için:
```bash
# Yeni ultimate bypass'ı al
curl http://localhost:8000/api/dast/ultimate/android

# Yeni üretim modlarını kullan
curl -X POST "http://localhost:8000/api/dast/generate/1?mode=ultimate"
```

### 1.0.0'dan 2.0.0'a

1. JWT secret için environment değişkenlerini güncelleyin
2. Yeni auth tabloları için veritabanı migrasyonlarını çalıştırın
3. Gerekirse rate limiting'i yapılandırın

---

## Katkıda Bulunanlar

- MobAI ekibi tarafından ilk geliştirme ve iyileştirmeler
- Topluluk bypass teknikleri ile Frida şablonları geliştirildi
