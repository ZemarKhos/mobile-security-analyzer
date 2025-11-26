# Mobile Analyzer

Android APK ve iOS IPA güvenlik analiz aracı - MobSF alternatifi.

## Özellikler

### Platform Desteği
- **Android APK**: Full decompile ve analiz
- **iOS IPA**: Binary analizi ve güvenlik taraması

### Güvenlik Analizi
- **Statik Kod Analizi (SAST)**: SQL injection, hardcoded secrets, weak crypto ve 20+ güvenlik pattern'i tespit eder
- **Manifest Analizi**: Permissions, components, exported services ve güvenlik konfigürasyonlarını inceler
- **Sertifika Analizi**: Debug certificate, expired certificate ve self-signed kontrolleri
- **Binary Analizi**: Native libraries, DEX files ve binary korumalarını analiz eder
- **Risk Skorlama**: Bulguları ağırlıklandırarak 0-100 arası risk skoru hesaplar

### Root/Jailbreak & SSL Pinning Tespiti
- **Root Detection**: 20+ pattern ile root kontrollerini tespit (SafetyNet, RootBeer, native checks vb.)
- **SSL Pinning**: OkHttp, Retrofit, TrustManager, Network Security Config analizi
- **Anti-Tampering**: Signature verification, integrity checks
- **iOS Jailbreak**: Cydia, substrate, common jailbreak paths
- **iOS SSL**: NSURLSession, ATS, custom trust evaluation

### Kullanıcı Tanımlı Güvenlik Kuralları
- Web arayüzünden kural ekleme/düzenleme/silme
- Regex veya plain text pattern desteği
- Platform bazlı filtreleme (Android/iOS/Both)
- Severity ve bypass difficulty ayarlama
- Built-in kuralları disable etme

### AI Entegrasyonu (Frida Script Üretimi)
- OpenAI, Anthropic Claude, Google Gemini, Ollama desteği
- Tespit edilen güvenlik mekanizmalarına göre otomatik Frida bypass script üretimi
- Custom prompt ile özelleştirilebilir script generation

### Dark Mode
- Sistem tercihine göre otomatik tema seçimi
- Manuel light/dark mode geçişi
- Tüm sayfalarda tutarlı dark theme desteği

## Teknoloji Stack

### Backend
- Python 3.11+
- FastAPI
- SQLite (aiosqlite)
- Pydantic
- APKTool (APK decompile)

### Frontend
- React 18 (Vite)
- TypeScript
- Tailwind CSS
- Lucide Icons
- DataTables (büyük veri setleri için)

### Altyapı
- Docker & Docker Compose
- Nginx reverse proxy

## Kurulum

### Docker ile (Önerilen)

```bash
# Projeyi klonla
git clone <repo-url>
cd MobAI

# Docker ile başlat
docker-compose up -d

# Tarayıcıda aç
open http://localhost:3000
```

### Manuel Kurulum

#### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate
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

1. Ana sayfada "Upload APK/IPA" butonuna tıklayın
2. APK veya IPA dosyasını sürükle-bırak veya seçin
3. Analiz otomatik başlayacak
4. Tamamlandığında comprehensive dashboard'u görüntüleyin

### Security Rules Yönetimi
1. Navigation'dan "Security Rules" sayfasına gidin
2. "Seed Defaults" ile 47 varsayılan kuralı yükleyin
3. "Add Rule" ile yeni kural ekleyin
4. Mevcut kuralları düzenleyin, disable edin veya silin

### AI ile Frida Script Üretimi
1. Bir rapor açın ve "AI Analysis" sekmesine gidin
2. "AI Settings" sayfasından AI provider yapılandırın
3. "Generate Frida Script" butonuna tıklayın

## API Endpoints

### Reports
- `GET /api/reports` - Tüm raporları listele
- `GET /api/reports/{id}` - Rapor detayı
- `DELETE /api/reports/{id}` - Raporu sil

### Findings (Pagination)
- `GET /api/reports/{id}/findings?page=1&page_size=100` - Paginated findings
- `GET /api/reports/{id}/findings/summary` - Finding istatistikleri

### Upload
- `POST /api/upload` - APK/IPA yükle ve analiz başlat

### Security Rules
- `GET /api/rules` - Tüm kuralları listele (filter: type, platform, enabled_only)
- `POST /api/rules` - Yeni kural oluştur
- `GET /api/rules/{id}` - Kural detayı
- `PUT /api/rules/{id}` - Kural güncelle
- `DELETE /api/rules/{id}` - Kural sil (built-in ise disable)
- `POST /api/rules/{id}/toggle` - Kuralı aç/kapat
- `POST /api/rules/seed` - Varsayılan kuralları yükle
- `GET /api/rules/categories/list` - Kategorileri listele

### AI Integration
- `GET /api/ai/providers` - Desteklenen AI provider'ları
- `GET /api/ai/config` - Mevcut AI yapılandırması
- `POST /api/ai/config` - AI yapılandır
- `DELETE /api/ai/config` - AI yapılandırmasını sil
- `POST /api/ai/test` - AI bağlantısını test et
- `GET /api/ai/security-scan/{id}` - Güvenlik mekanizmaları taraması
- `POST /api/ai/generate-frida/{id}` - Frida bypass script üret

## Kural Tipleri

| Tip | Açıklama | Platform |
|-----|----------|----------|
| `root_detection` | Root/SU binary kontrolleri | Android |
| `ssl_pinning` | SSL certificate pinning | Android |
| `anti_tampering` | Integrity/signature checks | Android |
| `ios_jailbreak` | Jailbreak tespiti | iOS |
| `ios_ssl_pinning` | iOS SSL pinning | iOS |

## Geliştirme

### Yeni Security Pattern Ekleme

Web arayüzünden veya API ile:

```bash
curl -X POST http://localhost:3000/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom Root Check",
    "type": "root_detection",
    "category": "custom_checks",
    "pattern": "isRooted|checkRoot",
    "is_regex": true,
    "description": "Custom root detection pattern",
    "severity": "high",
    "bypass_difficulty": "medium",
    "platform": "android"
  }'
```

### Backend'de Manuel Pattern Ekleme

`backend/root_ssl_scanner.py` dosyasında pattern dict'lerine ekleyin.

## Ekran Görüntüleri

- **Ana Sayfa**: APK/IPA yükleme arayüzü
- **Reports**: Analiz sonuçları listesi
- **Report Detail**: Comprehensive security dashboard
- **Security Rules**: Kural yönetim arayüzü
- **AI Settings**: AI provider yapılandırması

## Lisans

MIT
