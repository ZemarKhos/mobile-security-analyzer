"""
DAST (Dynamic Application Security Testing) API
Provides Frida script templates and runtime analysis hooks
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

from frida_templates import (
    get_template,
    get_templates_by_category,
    get_templates_by_platform,
    get_all_templates,
    combine_scripts,
    generate_custom_script,
    generate_ultimate_bypass,
    BypassCategory,
    FridaTemplate,
    FRIDA_TEMPLATES
)
from models.database import ReportRepository, FindingRepository
from root_ssl_scanner import scan_for_security_mechanisms
from logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/dast", tags=["DAST & Frida"])


# ============================================
# Pydantic Models
# ============================================

class TemplateInfo(BaseModel):
    """Template information response"""
    id: str
    name: str
    category: str
    platform: str
    description: str
    targets: List[str]
    difficulty: str


class TemplateResponse(BaseModel):
    """Full template with script"""
    id: str
    name: str
    category: str
    platform: str
    description: str
    targets: List[str]
    difficulty: str
    script: str


class CombineScriptsRequest(BaseModel):
    """Request to combine multiple scripts"""
    template_ids: List[str] = Field(..., min_length=1, description="List of template IDs to combine")


class GenerateScriptRequest(BaseModel):
    """Request for custom script generation"""
    report_id: int
    include_ssl_bypass: bool = True
    include_root_bypass: bool = True
    include_anti_debug: bool = True
    include_traffic_intercept: bool = False
    include_native_bypass: bool = False
    include_flutter_bypass: bool = False
    include_emulator_bypass: bool = False
    custom_classes: Optional[List[str]] = None


class HookGeneratorRequest(BaseModel):
    """Request to generate custom hooks"""
    class_name: str = Field(..., description="Fully qualified class name")
    method_name: str = Field(..., description="Method name to hook")
    platform: str = Field("android", description="Target platform")
    log_arguments: bool = True
    log_return_value: bool = True
    modify_return: Optional[str] = None


class RuntimeAnalysisConfig(BaseModel):
    """Configuration for runtime analysis"""
    target_package: str
    hooks: List[Dict[str, Any]]
    trace_calls: bool = False
    dump_memory: bool = False
    intercept_network: bool = True


# ============================================
# Template Endpoints
# ============================================

@router.get("/templates", response_model=List[TemplateInfo])
async def list_templates(
    category: Optional[str] = Query(None, description="Filter by category"),
    platform: Optional[str] = Query(None, description="Filter by platform (android/ios)")
):
    """
    List available Frida bypass templates.

    Categories:
    - root_detection: Root/su detection bypass (including KernelSU, Magisk)
    - ssl_pinning: SSL certificate pinning bypass (30+ libraries supported)
    - anti_tampering: Anti-tampering protection bypass
    - anti_debug: Anti-debugging/Anti-Frida bypass
    - emulator_detection: Emulator detection bypass
    - jailbreak_detection: iOS jailbreak detection bypass
    - traffic_interception: HTTP/HTTPS traffic capture
    - flutter_bypass: Flutter-specific SSL pinning bypass
    """
    if category:
        try:
            cat = BypassCategory(category)
            templates = get_templates_by_category(cat)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid category: {category}")
    elif platform:
        if platform not in ["android", "ios", "both"]:
            raise HTTPException(status_code=400, detail="Invalid platform")
        templates = get_templates_by_platform(platform)
    else:
        templates = get_all_templates()

    return [
        TemplateInfo(
            id=t.id,
            name=t.name,
            category=t.category.value,
            platform=t.platform,
            description=t.description,
            targets=t.targets,
            difficulty=t.difficulty
        )
        for t in templates
    ]


@router.get("/templates/{template_id}", response_model=TemplateResponse)
async def get_template_by_id(template_id: str):
    """Get a specific template with its script"""
    template = get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    return TemplateResponse(
        id=template.id,
        name=template.name,
        category=template.category.value,
        platform=template.platform,
        description=template.description,
        targets=template.targets,
        difficulty=template.difficulty,
        script=template.script
    )


@router.get("/templates/categories/list")
async def list_categories():
    """List all available bypass categories"""
    return {
        "categories": [
            {
                "id": cat.value,
                "name": cat.value.replace("_", " ").title(),
                "count": len(get_templates_by_category(cat))
            }
            for cat in BypassCategory
        ]
    }


@router.post("/templates/combine")
async def combine_template_scripts(request: CombineScriptsRequest):
    """
    Combine multiple templates into a single script.

    Useful for creating comprehensive bypass scripts.
    """
    # Validate all template IDs
    invalid_ids = [tid for tid in request.template_ids if tid not in FRIDA_TEMPLATES]
    if invalid_ids:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid template IDs: {invalid_ids}"
        )

    combined = combine_scripts(request.template_ids)

    return {
        "templates_used": request.template_ids,
        "script": combined
    }


# ============================================
# Report-based Script Generation
# ============================================

@router.post("/generate/{report_id}")
async def generate_bypass_script(
    report_id: int,
    include_traffic_intercept: bool = Query(False, description="Include HTTP traffic interception"),
    include_native_bypass: bool = Query(False, description="Include native-level (libc.so) bypasses"),
    mode: str = Query("auto", description="Generation mode: auto, mega, or ultimate")
):
    """
    Generate a customized Frida bypass script based on report findings.

    Analyzes the report's security findings and generates a script
    targeting the specific protection mechanisms detected.

    Modes:
    - auto: Automatically select templates based on findings
    - mega: Include the MEGA SSL bypass (30+ libraries)
    - ultimate: Include ALL available bypass techniques
    """
    # Get report
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report["status"] != "completed":
        raise HTTPException(status_code=400, detail="Report analysis not completed")

    platform = report.get("platform", "android")

    # Get findings
    findings_data = await FindingRepository.get_paginated(report_id, page=1, page_size=1000)
    findings = findings_data.get("findings", [])

    # Categorize findings by type
    root_findings = [f for f in findings if "root" in f.get("type", "").lower() or "su" in f.get("type", "").lower()]
    ssl_findings = [f for f in findings if "ssl" in f.get("type", "").lower() or "pinning" in f.get("type", "").lower()]
    jailbreak_findings = [f for f in findings if "jailbreak" in f.get("type", "").lower()]
    emulator_findings = [f for f in findings if "emulator" in f.get("type", "").lower()]
    flutter_findings = [f for f in findings if "flutter" in f.get("type", "").lower()]

    # Build findings structure for template generation
    findings_for_gen = {
        "root_detection": root_findings,
        "ssl_pinning": ssl_findings,
        "jailbreak_detection": jailbreak_findings,
        "emulator_detection": emulator_findings,
        "flutter": flutter_findings
    }

    # Generate script based on mode
    templates_used = []
    if mode == "ultimate":
        script = generate_ultimate_bypass(platform)
        templates_used = [
            "android_root_generic", "android_rootbeer", "android_magisk",
            "android_emulator", "android_native", "android_ssl_mega",
            "android_flutter_ssl", "android_anti_debug"
        ] if platform == "android" else ["ios_jailbreak", "ios_ssl"]
    else:
        script = generate_custom_script(
            findings_for_gen,
            platform,
            include_traffic_intercept=include_traffic_intercept,
            include_native_bypass=include_native_bypass
        )

        # Determine which templates were included based on findings
        if platform == "android":
            templates_used.append("android_root_generic")
            if any("rootbeer" in str(f).lower() for f in findings):
                templates_used.append("android_rootbeer")
            if any("magisk" in str(f).lower() for f in findings):
                templates_used.append("android_magisk")
            if emulator_findings:
                templates_used.append("android_emulator")
            if ssl_findings or mode == "mega":
                templates_used.append("android_ssl_mega")
            if flutter_findings or any("flutter" in str(f).lower() for f in findings):
                templates_used.append("android_flutter_ssl")
            if include_native_bypass:
                templates_used.append("android_native")
            if include_traffic_intercept:
                templates_used.append("android_traffic_intercept")
            templates_used.append("android_anti_debug")
        else:
            templates_used = ["ios_master", "ios_ssl"]

    logger.info(
        "Generated bypass script",
        extra_data={
            "report_id": report_id,
            "platform": platform,
            "mode": mode,
            "templates": templates_used,
            "findings_count": len(findings)
        }
    )

    return {
        "report_id": report_id,
        "platform": platform,
        "app_name": report.get("app_name"),
        "mode": mode,
        "templates_used": templates_used,
        "detection_summary": {
            "root_detection": len(root_findings),
            "ssl_pinning": len(ssl_findings),
            "jailbreak": len(jailbreak_findings),
            "emulator_detection": len(emulator_findings),
            "flutter": len(flutter_findings)
        },
        "script": script,
        "usage": {
            "android": "frida -U -f <package_name> -l script.js --no-pause",
            "ios": "frida -U -f <bundle_id> -l script.js --no-pause"
        },
        "tips": [
            "Use 'ultimate' mode for heavily protected apps",
            "Enable native bypass for apps with libc.so level checks",
            "Enable traffic intercept to capture API communications",
            "Use Frida 16+ for best compatibility"
        ]
    }


# ============================================
# Custom Hook Generator
# ============================================

@router.post("/hooks/generate")
async def generate_custom_hook(request: HookGeneratorRequest):
    """
    Generate a custom Frida hook for a specific class and method.

    Useful for creating targeted hooks during dynamic analysis.
    """
    if request.platform == "android":
        script = _generate_android_hook(request)
    elif request.platform == "ios":
        script = _generate_ios_hook(request)
    else:
        raise HTTPException(status_code=400, detail="Invalid platform")

    return {
        "class_name": request.class_name,
        "method_name": request.method_name,
        "platform": request.platform,
        "script": script
    }


def _generate_android_hook(request: HookGeneratorRequest) -> str:
    """Generate Android-specific hook"""
    log_args = ""
    if request.log_arguments:
        log_args = '''
        console.log("[*] Arguments:");
        for (var i = 0; i < arguments.length; i++) {
            console.log("    arg[" + i + "]: " + arguments[i]);
        }'''

    log_ret = ""
    if request.log_return_value:
        log_ret = '''
        console.log("[*] Return value: " + retval);'''

    modify_ret = ""
    if request.modify_return:
        modify_ret = f'''
        // Modify return value
        retval = {request.modify_return};
        console.log("[*] Modified return to: " + retval);'''

    return f'''/**
 * Custom Hook for {request.class_name}.{request.method_name}
 * Generated by Mobile Security Analyzer
 */

Java.perform(function() {{
    console.log("[*] Hooking {request.class_name}.{request.method_name}...");

    try {{
        var targetClass = Java.use("{request.class_name}");

        // Hook all overloads
        targetClass.{request.method_name}.overloads.forEach(function(overload) {{
            overload.implementation = function() {{
                console.log("[+] {request.method_name}() called");
                {log_args}

                // Call original method
                var retval = this.{request.method_name}.apply(this, arguments);
                {log_ret}
                {modify_ret}

                return retval;
            }};
        }});

        console.log("[*] Hook installed successfully");
    }} catch (e) {{
        console.log("[-] Error hooking: " + e);
    }}
}});
'''


def _generate_ios_hook(request: HookGeneratorRequest) -> str:
    """Generate iOS-specific hook"""
    log_args = ""
    if request.log_arguments:
        log_args = '''
    console.log("[*] Arguments: " + args.length);
    for (var i = 2; i < args.length; i++) {
        console.log("    arg[" + (i-2) + "]: " + ObjC.Object(args[i]));
    }'''

    log_ret = ""
    if request.log_return_value:
        log_ret = '''
    console.log("[*] Return value: " + retval);'''

    return f'''/**
 * Custom Hook for {request.class_name} {request.method_name}
 * Generated by Mobile Security Analyzer
 */

if (ObjC.available) {{
    console.log("[*] Hooking {request.class_name} {request.method_name}...");

    try {{
        var targetClass = ObjC.classes.{request.class_name};
        if (targetClass) {{
            Interceptor.attach(targetClass["{request.method_name}"].implementation, {{
                onEnter: function(args) {{
                    console.log("[+] {request.method_name} called");
                    {log_args}
                }},
                onLeave: function(retval) {{
                    {log_ret}
                }}
            }});
            console.log("[*] Hook installed successfully");
        }} else {{
            console.log("[-] Class not found");
        }}
    }} catch (e) {{
        console.log("[-] Error hooking: " + e);
    }}
}} else {{
    console.log("[-] ObjC runtime not available");
}}
'''


# ============================================
# Trace Scripts
# ============================================

@router.get("/trace/crypto/{platform}")
async def get_crypto_trace_script(platform: str):
    """
    Get a script to trace cryptographic operations.

    Useful for finding encryption keys, IVs, and encrypted data.
    """
    if platform == "android":
        script = '''/**
 * Android Crypto Tracing Script
 * Hooks common crypto APIs to dump keys and data
 */

Java.perform(function() {
    console.log("[*] Starting Crypto Trace...");

    // Cipher
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.getInstance.overload("java.lang.String").implementation = function(algo) {
        console.log("[Cipher] Algorithm: " + algo);
        return this.getInstance(algo);
    };

    Cipher.init.overload("int", "java.security.Key").implementation = function(mode, key) {
        var keyBytes = key.getEncoded();
        console.log("[Cipher] Mode: " + (mode == 1 ? "ENCRYPT" : "DECRYPT"));
        console.log("[Cipher] Key: " + bytesToHex(keyBytes));
        return this.init(mode, key);
    };

    Cipher.doFinal.overload("[B").implementation = function(data) {
        console.log("[Cipher] Input (" + data.length + " bytes): " + bytesToHex(data));
        var result = this.doFinal(data);
        console.log("[Cipher] Output (" + result.length + " bytes): " + bytesToHex(result));
        return result;
    };

    // SecretKeySpec
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(key, algo) {
        console.log("[SecretKeySpec] Algorithm: " + algo);
        console.log("[SecretKeySpec] Key: " + bytesToHex(key));
        return this.$init(key, algo);
    };

    // IvParameterSpec
    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
    IvParameterSpec.$init.overload("[B").implementation = function(iv) {
        console.log("[IvParameterSpec] IV: " + bytesToHex(iv));
        return this.$init(iv);
    };

    // MessageDigest
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.digest.overload("[B").implementation = function(data) {
        console.log("[MessageDigest] Input: " + bytesToHex(data));
        var hash = this.digest(data);
        console.log("[MessageDigest] Hash: " + bytesToHex(hash));
        return hash;
    };

    function bytesToHex(bytes) {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(("0" + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join("");
    }

    console.log("[*] Crypto Trace Active");
});
'''
    elif platform == "ios":
        script = '''/**
 * iOS Crypto Tracing Script
 * Hooks CommonCrypto and Security framework
 */

if (ObjC.available) {
    console.log("[*] Starting iOS Crypto Trace...");

    // CCCrypt
    var CCCrypt = Module.findExportByName("libcommonCrypto.dylib", "CCCrypt");
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function(args) {
                this.op = args[0].toInt32() == 0 ? "ENCRYPT" : "DECRYPT";
                this.keyLength = args[4].toInt32();
                this.dataLength = args[6].toInt32();

                console.log("[CCCrypt] Operation: " + this.op);
                console.log("[CCCrypt] Key Length: " + this.keyLength);
                console.log("[CCCrypt] Data Length: " + this.dataLength);

                // Dump key
                console.log("[CCCrypt] Key: " + hexdump(args[3], { length: this.keyLength }));
            },
            onLeave: function(retval) {
                console.log("[CCCrypt] Result: " + retval);
            }
        });
    }

    // SecKeyEncrypt
    var SecKeyEncrypt = Module.findExportByName("Security", "SecKeyCreateEncryptedData");
    if (SecKeyEncrypt) {
        Interceptor.attach(SecKeyEncrypt, {
            onEnter: function(args) {
                console.log("[SecKey] Encrypting data...");
            }
        });
    }

    console.log("[*] iOS Crypto Trace Active");

} else {
    console.log("[-] ObjC not available");
}
'''
    else:
        raise HTTPException(status_code=400, detail="Invalid platform")

    return {
        "platform": platform,
        "description": "Traces cryptographic operations to capture keys, IVs, and data",
        "script": script
    }


@router.get("/trace/network/{platform}")
async def get_network_trace_script(platform: str):
    """
    Get a script to trace network requests and responses.
    """
    if platform == "android":
        script = '''/**
 * Android Network Tracing Script
 */

Java.perform(function() {
    console.log("[*] Starting Network Trace...");

    // OkHttp3 Interceptor
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Builder = Java.use("okhttp3.OkHttpClient$Builder");
        var Interceptor = Java.use("okhttp3.Interceptor");

        console.log("[*] OkHttp3 found, tracing requests...");

        var Request = Java.use("okhttp3.Request");
        var Response = Java.use("okhttp3.Response");

        // Hook newCall to log requests
        OkHttpClient.newCall.implementation = function(request) {
            console.log("\\n[OkHttp] === REQUEST ===");
            console.log("[OkHttp] URL: " + request.url().toString());
            console.log("[OkHttp] Method: " + request.method());

            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log("[OkHttp] Header: " + headers.name(i) + ": " + headers.value(i));
            }

            return this.newCall(request);
        };
    } catch (e) {
        console.log("[-] OkHttp3 not found");
    }

    // HttpURLConnection
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            console.log("[URL] Opening connection: " + this.toString());
            return this.openConnection();
        };
    } catch (e) {}

    console.log("[*] Network Trace Active");
});
'''
    elif platform == "ios":
        script = '''/**
 * iOS Network Tracing Script
 */

if (ObjC.available) {
    console.log("[*] Starting iOS Network Trace...");

    // NSURLSession
    var NSURLSession = ObjC.classes.NSURLSession;
    Interceptor.attach(NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
        onEnter: function(args) {
            var request = ObjC.Object(args[2]);
            console.log("\\n[NSURLSession] === REQUEST ===");
            console.log("[NSURLSession] URL: " + request.URL().absoluteString());
            console.log("[NSURLSession] Method: " + request.HTTPMethod());
        }
    });

    console.log("[*] iOS Network Trace Active");
}
'''
    else:
        raise HTTPException(status_code=400, detail="Invalid platform")

    return {
        "platform": platform,
        "description": "Traces network requests to capture URLs, headers, and data",
        "script": script
    }


# ============================================
# Quick Start Scripts
# ============================================

@router.get("/quickstart/{platform}")
async def get_quickstart_script(
    platform: str,
    bypass_type: str = Query("all", description="Type: all, root, ssl, jailbreak, emulator, flutter, mega, ultimate")
):
    """
    Get a ready-to-use quickstart script for common bypass scenarios.

    Bypass types:
    - all: Standard combined bypass
    - root: Root detection bypass only (includes KernelSU)
    - ssl: SSL pinning bypass only
    - jailbreak: iOS jailbreak detection bypass
    - emulator: Emulator detection bypass
    - flutter: Flutter SSL pinning bypass
    - mega: MEGA SSL bypass (30+ libraries)
    - ultimate: ALL bypass techniques combined
    """
    if platform == "android":
        if bypass_type == "root":
            template = get_template("android_root_generic")
        elif bypass_type == "ssl":
            template = get_template("android_ssl_universal")
        elif bypass_type == "emulator":
            template = get_template("android_emulator")
        elif bypass_type == "flutter":
            template = get_template("android_flutter_ssl")
        elif bypass_type == "mega":
            template = get_template("android_ssl_mega")
        elif bypass_type == "ultimate":
            # Return ultimate bypass script
            script = generate_ultimate_bypass("android")
            return {
                "platform": platform,
                "bypass_type": "ultimate",
                "template_name": "Ultimate Bypass Script",
                "description": "Combines ALL bypass techniques: root, emulator, native, SSL (30+ libs), Flutter, anti-debug",
                "script": script,
                "usage": "frida -U -f <package_name> -l script.js --no-pause",
                "tips": [
                    "This is the most comprehensive bypass script",
                    "Use for heavily protected apps",
                    "May take longer to initialize due to all hooks",
                    "Includes native-level (libc.so) bypasses"
                ]
            }
        else:
            template = get_template("android_master")
    elif platform == "ios":
        if bypass_type == "jailbreak":
            template = get_template("ios_jailbreak")
        elif bypass_type == "ssl":
            template = get_template("ios_ssl")
        elif bypass_type == "ultimate":
            script = generate_ultimate_bypass("ios")
            return {
                "platform": platform,
                "bypass_type": "ultimate",
                "template_name": "Ultimate iOS Bypass Script",
                "description": "Combines jailbreak detection and SSL pinning bypasses",
                "script": script,
                "usage": "frida -U -f <bundle_id> -l script.js --no-pause",
                "tips": [
                    "Comprehensive iOS bypass",
                    "Covers SecTrustEvaluate, AFNetworking, TrustKit"
                ]
            }
        else:
            template = get_template("ios_master")
    else:
        raise HTTPException(status_code=400, detail="Invalid platform")

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    usage_cmd = f"frida -U -f <{'package_name' if platform == 'android' else 'bundle_id'}> -l script.js --no-pause"

    return {
        "platform": platform,
        "bypass_type": bypass_type,
        "template_name": template.name,
        "description": template.description,
        "script": template.script,
        "usage": usage_cmd,
        "tips": [
            "Use -f flag to spawn the app with Frida attached",
            "Add --no-pause to let the app continue after injection",
            "Use -U for USB-connected devices",
            "Check 'frida-ps -U' to find the correct package/bundle ID"
        ]
    }


@router.get("/ultimate/{platform}")
async def get_ultimate_bypass(platform: str):
    """
    Get the ultimate bypass script with ALL techniques combined.

    This is the most comprehensive bypass script available, combining:
    - Android: Root (KernelSU/Magisk), Emulator, Native (libc.so), SSL (30+ libs), Flutter, Anti-Debug
    - iOS: Jailbreak, SSL Pinning (AFNetworking, TrustKit, SecTrust)

    Use this for heavily protected applications.
    """
    if platform not in ["android", "ios"]:
        raise HTTPException(status_code=400, detail="Invalid platform. Use 'android' or 'ios'")

    script = generate_ultimate_bypass(platform)

    if platform == "android":
        templates_included = [
            "android_root_generic (KernelSU, Magisk, 40+ paths)",
            "android_rootbeer",
            "android_magisk",
            "android_emulator",
            "android_native (libc.so hooks)",
            "android_ssl_mega (30+ libraries)",
            "android_flutter_ssl",
            "android_anti_debug"
        ]
    else:
        templates_included = [
            "ios_jailbreak",
            "ios_ssl (AFNetworking, TrustKit, SecTrust)"
        ]

    return {
        "platform": platform,
        "name": "Ultimate Bypass Script",
        "description": "The most comprehensive bypass script combining ALL techniques",
        "templates_included": templates_included,
        "script": script,
        "usage": {
            "command": f"frida -U -f <{'package_name' if platform == 'android' else 'bundle_id'}> -l script.js --no-pause",
            "save_as": "ultimate_bypass.js"
        },
        "warnings": [
            "This script hooks many classes - may affect app performance",
            "Some apps may detect the large number of hooks",
            "For targeted bypass, use the /generate endpoint instead"
        ],
        "features": {
            "root_detection": "KernelSU, Magisk, SuperSU, 40+ paths, Package Manager",
            "emulator_detection": "Build properties, TelephonyManager, Sensor checks",
            "native_bypass": "libc.so: fopen, access, system, stat, strstr",
            "ssl_pinning": "30+ libraries including OkHttp, Trustkit, Conscrypt, Cronet",
            "flutter_ssl": "libflutter.so pattern matching",
            "anti_debug": "Debug.isDebuggerConnected, TracerPid, Frida detection"
        } if platform == "android" else {
            "jailbreak_detection": "File checks, URL schemes, sandbox escape",
            "ssl_pinning": "SecTrustEvaluate, AFNetworking, TrustKit"
        }
    }
