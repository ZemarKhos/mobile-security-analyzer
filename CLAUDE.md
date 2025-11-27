# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Mobile Security Analyzer (MobAI) is an Android APK and iOS IPA security analysis tool, serving as a MobSF alternative. It performs static analysis including SAST, manifest analysis, certificate analysis, binary analysis, root/jailbreak detection, CVE matching, and AI-powered Frida script generation with comprehensive DAST support.

## Build & Run Commands

### Docker (Recommended)
```bash
docker-compose up -d              # Start all services
docker-compose down               # Stop all services
docker-compose logs -f backend    # View backend logs
```
Access at http://localhost:3000

### Manual Development

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev      # Development server
npm run build    # Production build
npm run lint     # ESLint
```

### Environment Variables
```bash
# Backend
JWT_SECRET_KEY=<secret>           # JWT signing key (auto-generated if not set)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
MAX_FILE_SIZE=209715200           # Max upload size (200MB default)
LOG_LEVEL=INFO                    # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT=json                   # json or text
NVD_API_KEY=<key>                 # Optional, for CVE lookups
```

## Architecture

### Backend (Python/FastAPI)

**Core Analysis:**
- `main.py` - Application entry, file upload, analysis orchestration with rate limiting
- `scanner.py` - APK analysis using androguard (manifest, certificate, binary)
- `advanced_scanner.py` - SAST analysis with 23+ security pattern categories
- `ipa_scanner.py` - iOS IPA analysis (plist, entitlements, binary)
- `root_ssl_scanner.py` - Root detection, SSL pinning, anti-tampering patterns

**API Routes:**
- `auth_api.py` - JWT authentication (register, login, user management)
- `reports_api.py` - Reports CRUD and findings pagination
- `rules_api.py` - Custom security rules management
- `ai_api.py` - AI provider configuration and Frida script generation
- `export_api.py` - PDF/CSV/JSON export endpoints
- `cve_api.py` - CVE database search and report matching
- `compare_api.py` - Report version comparison
- `dast_api.py` - DAST/Frida templates, custom hooks, trace scripts

**Services:**
- `auth.py` - JWT tokens, password hashing, RBAC (admin/analyst/viewer roles)
- `logger.py` - Structured JSON logging with request middleware
- `export_service.py` - PDF generation with ReportLab, CSV export
- `cve_service.py` - NVD API integration, known library CVE database
- `compare_service.py` - Report diff algorithms for version comparison
- `frida_templates.py` - Pre-built Frida bypass scripts (10+ templates)

**Data Layer:**
- `models/database.py` - SQLite async with repositories (Report, Finding, SecurityRule, User, AuditLog)
- `models/schemas.py` - Pydantic request/response models

### Frontend (React/TypeScript/Vite)

**Structure:**
- `src/App.tsx` - Route definitions with AuthProvider wrapper
- `src/contexts/AuthContext.tsx` - Authentication state management
- `src/lib/api.ts` - API client with JWT token handling and auto-refresh
- `src/types/api.ts` - TypeScript interfaces for all API types
- `src/pages/` - HomePage, ReportsPage, ComprehensiveReportPage, ComparePage, LoginPage, AISettingsPage, RulesPage
- `src/components/` - Layout, FileUpload, FindingsDataTable, RiskScore, SeverityBadge

### Data Flow
1. User uploads APK/IPA via `/api/upload` (rate limited: 10/minute)
2. File saved with SHA256 hash prefix, initial report created
3. Background task runs platform-specific analysis pipeline
4. Findings stored separately for pagination (`/api/reports/{id}/findings`)
5. CVE matching available post-analysis (`/api/cve/reports/{id}/match`)
6. Export to PDF/CSV/JSON via `/api/export/reports/{id}/{format}`
7. Generate Frida bypass scripts via `/api/dast/generate/{id}`

## Key Features (v2.0)

- **Authentication**: JWT-based with roles (admin, analyst, viewer), first user becomes admin
- **Rate Limiting**: Upload endpoint limited to prevent abuse
- **Export**: PDF reports with ReportLab, CSV findings export, JSON full export
- **CVE Matching**: NVD API integration + static library CVE database
- **Report Comparison**: Compare app versions to track security changes
- **Structured Logging**: JSON logging with request/analysis tracing
- **CORS Security**: Configurable allowed origins (not open by default)
- **DAST/Frida**: 10+ bypass templates, custom hook generator, crypto/network tracing

## DAST/Frida Features

**Bypass Templates:**
- `android_master` - Comprehensive Android bypass (root, SSL, anti-debug)
- `android_root_generic` - Generic root detection bypass
- `android_rootbeer` - RootBeer library bypass
- `android_magisk` - Magisk detection bypass
- `android_ssl_universal` - Universal SSL pinning bypass
- `android_anti_debug` - Anti-debug/anti-Frida bypass
- `ios_master` - Comprehensive iOS bypass (jailbreak, SSL)
- `ios_jailbreak` - Jailbreak detection bypass
- `ios_ssl` - iOS SSL pinning bypass

**API Endpoints:**
- `GET /api/dast/templates` - List all templates
- `GET /api/dast/templates/{id}` - Get template with script
- `POST /api/dast/generate/{report_id}` - Generate report-specific bypass
- `POST /api/dast/hooks/generate` - Generate custom hooks
- `GET /api/dast/trace/crypto/{platform}` - Crypto tracing script
- `GET /api/dast/trace/network/{platform}` - Network tracing script
- `GET /api/dast/quickstart/{platform}` - Ready-to-use scripts

## API Authentication

Protected endpoints require `Authorization: Bearer <token>` header. Token refresh handled automatically by frontend. First registered user gets admin role.

## API Base Path

All API endpoints prefixed with `/api`. Swagger docs at `/api/docs`, ReDoc at `/api/redoc`.
