"""
Pydantic Models for Mobile Analyzer
Defines all request/response schemas for the API
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"


# ==================== Finding Schemas ====================

class Finding(BaseModel):
    """Single security finding"""
    id: Optional[int] = None
    type: str = Field(..., description="Finding type (e.g., sql_injection, hardcoded_secret)")
    severity: SeverityLevel = SeverityLevel.INFO
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None


class FindingsSummary(BaseModel):
    """Summary statistics for findings"""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    by_type: Dict[str, int] = Field(default_factory=dict)


class PaginatedFindings(BaseModel):
    """Paginated findings response"""
    findings: List[Finding]
    total: int
    page: int
    page_size: int
    total_pages: int


# ==================== Manifest Analysis Schemas ====================

class Permission(BaseModel):
    """Android permission"""
    name: str
    protection_level: Optional[str] = None
    description: Optional[str] = None
    is_dangerous: bool = False


class Activity(BaseModel):
    """Android activity component"""
    name: str
    exported: bool = False
    permission: Optional[str] = None
    intent_filters: List[str] = Field(default_factory=list)


class Service(BaseModel):
    """Android service component"""
    name: str
    exported: bool = False
    permission: Optional[str] = None


class Receiver(BaseModel):
    """Android broadcast receiver"""
    name: str
    exported: bool = False
    permission: Optional[str] = None
    intent_filters: List[str] = Field(default_factory=list)


class Provider(BaseModel):
    """Android content provider"""
    name: str
    exported: bool = False
    permission: Optional[str] = None
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    authorities: Optional[str] = None


class ManifestAnalysis(BaseModel):
    """Complete manifest analysis result"""
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    permissions: List[Permission] = Field(default_factory=list)
    activities: List[Activity] = Field(default_factory=list)
    services: List[Service] = Field(default_factory=list)
    receivers: List[Receiver] = Field(default_factory=list)
    providers: List[Provider] = Field(default_factory=list)
    is_debuggable: bool = False
    allows_backup: bool = True
    uses_cleartext_traffic: bool = False
    findings: List[Finding] = Field(default_factory=list)


# ==================== Certificate Analysis Schemas ====================

class CertificateInfo(BaseModel):
    """Certificate information"""
    subject: Dict[str, str] = Field(default_factory=dict)
    issuer: Dict[str, str] = Field(default_factory=dict)
    serial_number: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    signature_algorithm: Optional[str] = None
    md5_fingerprint: Optional[str] = None
    sha1_fingerprint: Optional[str] = None
    sha256_fingerprint: Optional[str] = None


class CertificateAnalysis(BaseModel):
    """Complete certificate analysis result"""
    certificates: List[CertificateInfo] = Field(default_factory=list)
    is_debug_signed: bool = False
    is_expired: bool = False
    is_self_signed: bool = False
    findings: List[Finding] = Field(default_factory=list)


# ==================== Binary Analysis Schemas ====================

class BinaryProtection(BaseModel):
    """Binary protection check"""
    name: str
    description: str
    is_enabled: bool
    severity: SeverityLevel = SeverityLevel.INFO


class LibraryInfo(BaseModel):
    """Native library information"""
    name: str
    path: str
    architecture: Optional[str] = None
    is_stripped: bool = False


class BinaryAnalysis(BaseModel):
    """Complete binary analysis result"""
    apk_size: int = 0
    dex_count: int = 0
    native_libraries: List[LibraryInfo] = Field(default_factory=list)
    architectures: List[str] = Field(default_factory=list)
    protections: List[BinaryProtection] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)


# ==================== Code Analysis Schemas ====================

class CodeAnalysis(BaseModel):
    """Complete code analysis result"""
    total_files: int = 0
    total_lines: int = 0
    java_files: int = 0
    kotlin_files: int = 0
    smali_files: int = 0
    findings_summary: FindingsSummary = Field(default_factory=FindingsSummary)
    # Findings are NOT included here - fetched via pagination endpoint
    findings: List[Finding] = Field(default_factory=list)  # Only populated for small reports


# ==================== Report Schemas ====================

class ReportBase(BaseModel):
    """Base report fields"""
    app_name: str
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    file_name: str
    file_size: int
    md5_hash: str
    sha1_hash: str
    sha256_hash: str
    platform: Platform = Platform.ANDROID


class ReportCreate(ReportBase):
    """Report creation schema"""
    pass


class ReportSummary(BaseModel):
    """Summary for report list view"""
    id: int
    app_name: str
    package_name: str
    version_name: Optional[str] = None
    file_name: str
    platform: Platform = Platform.ANDROID
    status: AnalysisStatus
    risk_score: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    created_at: datetime
    completed_at: Optional[datetime] = None


class ReportDetail(ReportBase):
    """Complete report detail - findings excluded for performance"""
    id: int
    status: AnalysisStatus
    risk_score: int = 0
    created_at: datetime
    completed_at: Optional[datetime] = None
    
    # Analysis results
    manifest_analysis: Optional[ManifestAnalysis] = None
    certificate_analysis: Optional[CertificateAnalysis] = None
    binary_analysis: Optional[BinaryAnalysis] = None
    code_analysis: Optional[CodeAnalysis] = None
    
    # Summary statistics - findings are fetched via pagination
    findings_summary: FindingsSummary = Field(default_factory=FindingsSummary)
    
    class Config:
        from_attributes = True


# ==================== API Response Schemas ====================

class UploadResponse(BaseModel):
    """APK/IPA upload response"""
    report_id: int
    message: str
    status: AnalysisStatus
    platform: Platform = Platform.ANDROID


class ErrorResponse(BaseModel):
    """Error response"""
    detail: str
    code: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    timestamp: datetime
