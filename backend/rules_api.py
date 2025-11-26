"""
Security Rules API
Endpoints for managing root detection and SSL pinning patterns
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum

from models.database import SecurityRulesRepository

router = APIRouter(prefix="/api/rules", tags=["Security Rules"])


# ==================== Enums ====================

class RuleType(str, Enum):
    ROOT_DETECTION = "root_detection"
    SSL_PINNING = "ssl_pinning"
    ANTI_TAMPERING = "anti_tampering"
    IOS_JAILBREAK = "ios_jailbreak"
    IOS_SSL_PINNING = "ios_ssl_pinning"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BypassDifficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    ALL = "all"


# ==================== Request/Response Models ====================

class RuleCreate(BaseModel):
    """Schema for creating a new rule"""
    name: str = Field(..., min_length=3, max_length=100, description="Unique rule name")
    type: RuleType = Field(..., description="Type of security check")
    category: str = Field(..., min_length=2, max_length=50, description="Category within type")
    pattern: str = Field(..., min_length=2, description="Pattern to search for")
    is_regex: bool = Field(True, description="Whether pattern is regex")
    case_sensitive: bool = Field(False, description="Case sensitive matching")
    description: str = Field("", max_length=500, description="Rule description")
    severity: Severity = Field(Severity.INFO, description="Finding severity")
    bypass_difficulty: BypassDifficulty = Field(BypassDifficulty.MEDIUM)
    platform: Platform = Field(Platform.ANDROID, description="Target platform")
    is_enabled: bool = Field(True, description="Is rule active")


class RuleUpdate(BaseModel):
    """Schema for updating a rule"""
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    type: Optional[RuleType] = None
    category: Optional[str] = Field(None, min_length=2, max_length=50)
    pattern: Optional[str] = Field(None, min_length=2)
    is_regex: Optional[bool] = None
    case_sensitive: Optional[bool] = None
    description: Optional[str] = Field(None, max_length=500)
    severity: Optional[Severity] = None
    bypass_difficulty: Optional[BypassDifficulty] = None
    platform: Optional[Platform] = None
    is_enabled: Optional[bool] = None


class RuleResponse(BaseModel):
    """Schema for rule response"""
    id: int
    name: str
    type: str
    category: str
    pattern: str
    is_regex: bool
    case_sensitive: bool
    description: str
    severity: str
    bypass_difficulty: str
    platform: str
    is_enabled: bool
    is_builtin: bool
    created_at: str
    updated_at: str


class RuleListResponse(BaseModel):
    """Schema for rule list response"""
    rules: List[RuleResponse]
    total: int
    by_type: dict


# ==================== Endpoints ====================

@router.get("", response_model=RuleListResponse)
async def list_rules(
    type: Optional[RuleType] = Query(None, description="Filter by rule type"),
    platform: Optional[Platform] = Query(None, description="Filter by platform"),
    include_disabled: bool = Query(False, description="Include disabled rules")
):
    """
    List all security rules with optional filters.
    
    Use this to see all available detection patterns for root detection,
    SSL pinning, and other security mechanisms.
    """
    rules = await SecurityRulesRepository.get_all(
        rule_type=type.value if type else None,
        platform=platform.value if platform else None,
        enabled_only=not include_disabled
    )
    
    # Group by type for summary
    by_type = {}
    for rule in rules:
        rule_type = rule["type"]
        if rule_type not in by_type:
            by_type[rule_type] = 0
        by_type[rule_type] += 1
    
    return RuleListResponse(
        rules=[RuleResponse(**r) for r in rules],
        total=len(rules),
        by_type=by_type
    )


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: int):
    """Get a specific rule by ID"""
    rule = await SecurityRulesRepository.get_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return RuleResponse(**rule)


@router.post("", response_model=RuleResponse, status_code=201)
async def create_rule(rule: RuleCreate):
    """
    Create a new security detection rule.
    
    Example patterns:
    - Root detection: "com.scottyab.rootbeer" (package name)
    - SSL pinning: "CertificatePinner" (class name)
    - Regex: r"Runtime\\.getRuntime\\(\\)\\.exec.*su"
    """
    rule_data = rule.model_dump()
    rule_data["type"] = rule.type.value
    rule_data["severity"] = rule.severity.value
    rule_data["bypass_difficulty"] = rule.bypass_difficulty.value
    rule_data["platform"] = rule.platform.value
    rule_data["is_builtin"] = False
    
    try:
        rule_id = await SecurityRulesRepository.create(rule_data)
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(status_code=400, detail="Rule name already exists")
        raise HTTPException(status_code=500, detail=str(e))
    
    created_rule = await SecurityRulesRepository.get_by_id(rule_id)
    return RuleResponse(**created_rule)


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: int, rule: RuleUpdate):
    """
    Update an existing rule.
    
    Only non-null fields will be updated.
    """
    existing = await SecurityRulesRepository.get_by_id(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    update_data = rule.model_dump(exclude_none=True)
    
    # Convert enums to strings
    if "type" in update_data:
        update_data["type"] = update_data["type"].value
    if "severity" in update_data:
        update_data["severity"] = update_data["severity"].value
    if "bypass_difficulty" in update_data:
        update_data["bypass_difficulty"] = update_data["bypass_difficulty"].value
    if "platform" in update_data:
        update_data["platform"] = update_data["platform"].value
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    try:
        await SecurityRulesRepository.update(rule_id, update_data)
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(status_code=400, detail="Rule name already exists")
        raise HTTPException(status_code=500, detail=str(e))
    
    updated_rule = await SecurityRulesRepository.get_by_id(rule_id)
    return RuleResponse(**updated_rule)


@router.delete("/{rule_id}")
async def delete_rule(rule_id: int):
    """
    Delete a security rule.
    
    Built-in rules cannot be deleted, but will be disabled instead.
    """
    existing = await SecurityRulesRepository.get_by_id(rule_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    success = await SecurityRulesRepository.delete(rule_id)
    
    if existing["is_builtin"]:
        return {"message": "Built-in rule has been disabled", "rule_id": rule_id}
    
    return {"message": "Rule deleted successfully", "rule_id": rule_id}


@router.post("/{rule_id}/toggle")
async def toggle_rule(rule_id: int):
    """Toggle a rule's enabled status"""
    new_status = await SecurityRulesRepository.toggle_enabled(rule_id)
    
    if new_status is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return {
        "rule_id": rule_id,
        "is_enabled": new_status,
        "message": f"Rule {'enabled' if new_status else 'disabled'}"
    }


@router.post("/seed")
async def seed_default_rules():
    """
    Seed the database with default built-in rules.
    
    This will add all standard root detection and SSL pinning patterns.
    Existing rules with same names will be skipped.
    """
    # Check if already seeded
    count = await SecurityRulesRepository.get_count()
    if count > 0:
        return {"message": f"Database already has {count} rules", "seeded": 0}
    
    default_rules = get_default_rules()
    inserted = await SecurityRulesRepository.bulk_insert(default_rules)
    
    return {
        "message": f"Seeded {inserted} default rules",
        "seeded": inserted,
        "total_available": len(default_rules)
    }


@router.get("/categories/list")
async def list_categories():
    """Get all available rule categories grouped by type"""
    rules = await SecurityRulesRepository.get_all(enabled_only=False)
    
    categories = {}
    for rule in rules:
        rule_type = rule["type"]
        category = rule["category"]
        
        if rule_type not in categories:
            categories[rule_type] = set()
        categories[rule_type].add(category)
    
    # Convert sets to sorted lists
    return {
        rule_type: sorted(list(cats))
        for rule_type, cats in categories.items()
    }


def get_default_rules() -> List[dict]:
    """Get all default built-in rules"""
    rules = []
    
    # ==================== ROOT DETECTION RULES ====================
    
    # RootBeer Library
    rules.extend([
        {
            "name": "RootBeer Library",
            "type": "root_detection",
            "category": "RootBeer",
            "pattern": r"RootBeer",
            "description": "RootBeer library detection",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
        {
            "name": "RootBeer Package",
            "type": "root_detection",
            "category": "RootBeer",
            "pattern": r"com\.scottyab\.rootbeer",
            "description": "RootBeer package import",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
        {
            "name": "RootBeer isRooted",
            "type": "root_detection",
            "category": "RootBeer",
            "pattern": r"isRooted\(\)",
            "description": "RootBeer isRooted() method call",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
    ])
    
    # Build Tags Check
    rules.extend([
        {
            "name": "Build.TAGS Check",
            "type": "root_detection",
            "category": "BuildTags",
            "pattern": r"Build\.TAGS",
            "description": "Build.TAGS property check",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
        {
            "name": "ro.build.tags Property",
            "type": "root_detection",
            "category": "BuildTags",
            "pattern": r"ro\.build\.tags",
            "description": "System property ro.build.tags",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
        {
            "name": "test-keys String",
            "type": "root_detection",
            "category": "BuildTags",
            "pattern": r"test-keys",
            "description": "test-keys string check",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
    ])
    
    # Su Binary Detection
    rules.extend([
        {
            "name": "Su Binary /system/xbin",
            "type": "root_detection",
            "category": "SuBinary",
            "pattern": r"/system/xbin/su",
            "description": "Su binary at /system/xbin/su",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
        {
            "name": "Su Binary /system/bin",
            "type": "root_detection",
            "category": "SuBinary",
            "pattern": r"/system/bin/su",
            "description": "Su binary at /system/bin/su",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
        {
            "name": "Su Binary /sbin",
            "type": "root_detection",
            "category": "SuBinary",
            "pattern": r"/sbin/su",
            "description": "Su binary at /sbin/su",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
        {
            "name": "Which Su Command",
            "type": "root_detection",
            "category": "SuBinary",
            "pattern": r"which\s+su",
            "description": "which su command execution",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
    ])
    
    # Superuser Apps
    rules.extend([
        {
            "name": "Superuser.apk",
            "type": "root_detection",
            "category": "SuperuserApp",
            "pattern": r"Superuser\.apk",
            "description": "Superuser.apk detection",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
        {
            "name": "SuperSU Package",
            "type": "root_detection",
            "category": "SuperuserApp",
            "pattern": r"eu\.chainfire\.supersu",
            "description": "SuperSU package detection",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
        {
            "name": "Magisk Package",
            "type": "root_detection",
            "category": "SuperuserApp",
            "pattern": r"com\.topjohnwu\.magisk",
            "description": "Magisk package detection",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
    ])
    
    # BusyBox
    rules.extend([
        {
            "name": "BusyBox Binary",
            "type": "root_detection",
            "category": "BusyBox",
            "pattern": r"busybox",
            "case_sensitive": False,
            "description": "BusyBox binary detection",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
        {
            "name": "BusyBox Path",
            "type": "root_detection",
            "category": "BusyBox",
            "pattern": r"/system/xbin/busybox",
            "description": "BusyBox at system path",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
    ])
    
    # SafetyNet
    rules.extend([
        {
            "name": "SafetyNet API",
            "type": "root_detection",
            "category": "SafetyNet",
            "pattern": r"SafetyNet",
            "case_sensitive": False,
            "description": "Google SafetyNet API usage",
            "severity": "info",
            "bypass_difficulty": "hard",
            "platform": "android"
        },
        {
            "name": "SafetyNet Package",
            "type": "root_detection",
            "category": "SafetyNet",
            "pattern": r"com\.google\.android\.gms\.safetynet",
            "description": "SafetyNet GMS package",
            "severity": "info",
            "bypass_difficulty": "hard",
            "platform": "android"
        },
        {
            "name": "Play Integrity API",
            "type": "root_detection",
            "category": "SafetyNet",
            "pattern": r"PlayIntegrity",
            "case_sensitive": False,
            "description": "Play Integrity API usage",
            "severity": "info",
            "bypass_difficulty": "hard",
            "platform": "android"
        },
    ])
    
    # Root Cloaking Detection
    rules.extend([
        {
            "name": "Xposed Framework",
            "type": "root_detection",
            "category": "RootCloak",
            "pattern": r"de\.robv\.android\.xposed",
            "description": "Xposed Framework detection",
            "severity": "info",
            "bypass_difficulty": "hard",
            "platform": "android"
        },
        {
            "name": "XposedBridge Class",
            "type": "root_detection",
            "category": "RootCloak",
            "pattern": r"XposedBridge",
            "description": "XposedBridge class reference",
            "severity": "info",
            "bypass_difficulty": "hard",
            "platform": "android"
        },
    ])
    
    # ==================== SSL PINNING RULES ====================
    
    # TrustManager
    rules.extend([
        {
            "name": "X509TrustManager",
            "type": "ssl_pinning",
            "category": "TrustManager",
            "pattern": r"X509TrustManager",
            "description": "Custom X509TrustManager implementation",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
        {
            "name": "checkServerTrusted",
            "type": "ssl_pinning",
            "category": "TrustManager",
            "pattern": r"checkServerTrusted",
            "description": "Server certificate validation",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
        {
            "name": "checkClientTrusted",
            "type": "ssl_pinning",
            "category": "TrustManager",
            "pattern": r"checkClientTrusted",
            "description": "Client certificate validation",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
    ])
    
    # OkHttp Pinning
    rules.extend([
        {
            "name": "CertificatePinner",
            "type": "ssl_pinning",
            "category": "OkHttpPinning",
            "pattern": r"CertificatePinner",
            "description": "OkHttp CertificatePinner",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
        {
            "name": "SHA256 Pin Format",
            "type": "ssl_pinning",
            "category": "OkHttpPinning",
            "pattern": r"sha256/[A-Za-z0-9+/=]{43,44}",
            "description": "SHA256 certificate pin hash",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
    ])
    
    # Network Security Config
    rules.extend([
        {
            "name": "Network Security Config",
            "type": "ssl_pinning",
            "category": "NetworkSecurityConfig",
            "pattern": r"network_security_config",
            "description": "Android Network Security Configuration",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
        {
            "name": "Pin-Set Config",
            "type": "ssl_pinning",
            "category": "NetworkSecurityConfig",
            "pattern": r"pin-set",
            "description": "Certificate pin-set in config",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
    ])
    
    # HostnameVerifier
    rules.extend([
        {
            "name": "HostnameVerifier",
            "type": "ssl_pinning",
            "category": "HostnameVerifier",
            "pattern": r"HostnameVerifier",
            "description": "Custom HostnameVerifier",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
        {
            "name": "ALLOW_ALL_HOSTNAME_VERIFIER",
            "type": "ssl_pinning",
            "category": "HostnameVerifier",
            "pattern": r"ALLOW_ALL_HOSTNAME_VERIFIER",
            "description": "Insecure hostname verifier",
            "severity": "high",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
    ])
    
    # SSLSocketFactory
    rules.extend([
        {
            "name": "SSLSocketFactory",
            "type": "ssl_pinning",
            "category": "SSLSocketFactory",
            "pattern": r"SSLSocketFactory",
            "description": "Custom SSLSocketFactory",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
        {
            "name": "setSSLSocketFactory",
            "type": "ssl_pinning",
            "category": "SSLSocketFactory",
            "pattern": r"setSSLSocketFactory",
            "description": "Setting custom SSL factory",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
    ])
    
    # WebView SSL
    rules.extend([
        {
            "name": "onReceivedSslError",
            "type": "ssl_pinning",
            "category": "WebViewSSL",
            "pattern": r"onReceivedSslError",
            "description": "WebView SSL error handler",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
        {
            "name": "SslErrorHandler.proceed",
            "type": "ssl_pinning",
            "category": "WebViewSSL",
            "pattern": r"SslErrorHandler.*proceed",
            "description": "SSL error proceed (potential vulnerability)",
            "severity": "high",
            "bypass_difficulty": "easy",
            "platform": "android"
        },
    ])
    
    # ==================== ANTI-TAMPERING RULES ====================
    
    rules.extend([
        {
            "name": "Frida Detection",
            "type": "anti_tampering",
            "category": "AntiHook",
            "pattern": r"frida",
            "case_sensitive": False,
            "description": "Frida framework detection",
            "severity": "info",
            "bypass_difficulty": "hard",
            "platform": "android"
        },
        {
            "name": "Substrate Detection",
            "type": "anti_tampering",
            "category": "AntiHook",
            "pattern": r"substrate",
            "case_sensitive": False,
            "description": "Cydia Substrate detection",
            "severity": "info",
            "bypass_difficulty": "hard",
            "platform": "android"
        },
        {
            "name": "TracerPid Check",
            "type": "anti_tampering",
            "category": "AntiDebug",
            "pattern": r"TracerPid",
            "description": "Anti-debugging TracerPid check",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
        {
            "name": "ptrace Detection",
            "type": "anti_tampering",
            "category": "AntiDebug",
            "pattern": r"ptrace",
            "description": "ptrace anti-debugging",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "android"
        },
    ])
    
    # ==================== iOS JAILBREAK RULES ====================
    
    rules.extend([
        {
            "name": "Cydia URL Scheme",
            "type": "ios_jailbreak",
            "category": "JailbreakCheck",
            "pattern": r"cydia://",
            "description": "Cydia URL scheme check",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "ios"
        },
        {
            "name": "Cydia App Path",
            "type": "ios_jailbreak",
            "category": "JailbreakCheck",
            "pattern": r"/Applications/Cydia\.app",
            "description": "Cydia app path check",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "ios"
        },
        {
            "name": "Private Var Stash",
            "type": "ios_jailbreak",
            "category": "JailbreakCheck",
            "pattern": r"/private/var/stash",
            "description": "Jailbreak stash directory",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "ios"
        },
        {
            "name": "Substrate Library",
            "type": "ios_jailbreak",
            "category": "JailbreakCheck",
            "pattern": r"/Library/MobileSubstrate",
            "description": "Mobile Substrate library path",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "ios"
        },
        {
            "name": "SSH Port Check",
            "type": "ios_jailbreak",
            "category": "JailbreakCheck",
            "pattern": r"/usr/sbin/sshd",
            "description": "SSH daemon presence check",
            "severity": "info",
            "bypass_difficulty": "easy",
            "platform": "ios"
        },
    ])
    
    # ==================== iOS SSL PINNING RULES ====================
    
    rules.extend([
        {
            "name": "SecTrustEvaluate",
            "type": "ios_ssl_pinning",
            "category": "SecTrust",
            "pattern": r"SecTrustEvaluate",
            "description": "iOS certificate trust evaluation",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "ios"
        },
        {
            "name": "URLSessionDelegate",
            "type": "ios_ssl_pinning",
            "category": "URLSession",
            "pattern": r"URLSessionDelegate",
            "description": "Custom URLSession delegate",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "ios"
        },
        {
            "name": "didReceiveChallenge",
            "type": "ios_ssl_pinning",
            "category": "URLSession",
            "pattern": r"didReceiveChallenge",
            "description": "Authentication challenge handler",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "ios"
        },
        {
            "name": "TrustKit Framework",
            "type": "ios_ssl_pinning",
            "category": "TrustKit",
            "pattern": r"TrustKit",
            "description": "TrustKit SSL pinning framework",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "ios"
        },
        {
            "name": "Alamofire ServerTrustPolicy",
            "type": "ios_ssl_pinning",
            "category": "Alamofire",
            "pattern": r"ServerTrustPolicy",
            "description": "Alamofire server trust policy",
            "severity": "info",
            "bypass_difficulty": "medium",
            "platform": "ios"
        },
    ])
    
    # Set is_builtin for all
    for rule in rules:
        rule["is_builtin"] = True
        rule["is_enabled"] = True
        if "is_regex" not in rule:
            rule["is_regex"] = True
        if "case_sensitive" not in rule:
            rule["case_sensitive"] = False
    
    return rules
