"""
Advanced Scanner - Deep Code Analysis (SAST)
Performs comprehensive static analysis on decompiled source code
"""

import os
import re
import asyncio
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
import zipfile
import tempfile
import shutil


class AdvancedScanner:
    """Advanced static analysis scanner for decompiled APK code"""
    
    # Security patterns for code analysis
    SECURITY_PATTERNS = {
        # SQL Injection
        "sql_injection": {
            "patterns": [
                r'rawQuery\s*\(\s*["\'].*\+',
                r'execSQL\s*\(\s*["\'].*\+',
                r'query\s*\([^)]*\+[^)]*\)',
                r'rawQuery\s*\([^,]*\+',
            ],
            "severity": "high",
            "title": "Potential SQL Injection",
            "description": "SQL query appears to use string concatenation which may be vulnerable to SQL injection",
            "recommendation": "Use parameterized queries or prepared statements",
            "cwe_id": "CWE-89",
            "owasp_category": "M7"
        },
        
        # Hardcoded Secrets
        "hardcoded_secret": {
            "patterns": [
                r'(?i)(password|passwd|pwd|secret|api_key|apikey|api-key|private_key)\s*=\s*["\'][^"\']{8,}["\']',
                r'(?i)(aws_access_key|aws_secret|firebase|google_api)\s*=\s*["\'][^"\']+["\']',
                r'(?i)Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
                r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
                r'(?i)(token|auth|credential)\s*=\s*["\'][^"\']{16,}["\']',
            ],
            "severity": "critical",
            "title": "Hardcoded Secret/Credential",
            "description": "Sensitive credential or secret key appears to be hardcoded",
            "recommendation": "Store secrets in secure storage or environment variables",
            "cwe_id": "CWE-798",
            "owasp_category": "M9"
        },
        
        # Insecure Communication
        "insecure_http": {
            "patterns": [
                r'http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.)',
                r'setHostnameVerifier\s*\(\s*ALLOW_ALL',
                r'TrustAllCertificates',
                r'X509TrustManager.*checkServerTrusted.*\{\s*\}',
            ],
            "severity": "high",
            "title": "Insecure HTTP Connection",
            "description": "Application may use unencrypted HTTP connections",
            "recommendation": "Use HTTPS for all network communications",
            "cwe_id": "CWE-319",
            "owasp_category": "M3"
        },
        
        # Weak Cryptography
        "weak_crypto": {
            "patterns": [
                r'(?i)DES[^3]',
                r'(?i)MD5',
                r'(?i)SHA-?1(?![0-9])',
                r'(?i)RC4',
                r'(?i)ECB',
                r'Cipher\.getInstance\s*\(\s*["\']AES["\']',  # AES without mode
            ],
            "severity": "high",
            "title": "Weak Cryptographic Algorithm",
            "description": "Application uses weak or deprecated cryptographic algorithm",
            "recommendation": "Use strong algorithms like AES-256-GCM, SHA-256 or higher",
            "cwe_id": "CWE-327",
            "owasp_category": "M5"
        },
        
        # Insecure Random
        "insecure_random": {
            "patterns": [
                r'java\.util\.Random(?!\s*secure)',
                r'Math\.random\s*\(',
            ],
            "severity": "medium",
            "title": "Insecure Random Number Generator",
            "description": "Application uses non-cryptographic random number generator",
            "recommendation": "Use SecureRandom for security-sensitive operations",
            "cwe_id": "CWE-330",
            "owasp_category": "M5"
        },
        
        # Logging Sensitive Data
        "sensitive_logging": {
            "patterns": [
                r'Log\.[divwe]\s*\([^)]*(?i)(password|token|secret|key|credential)[^)]*\)',
                r'System\.out\.print.*(?i)(password|token|secret)',
                r'printStackTrace\s*\(\s*\)',
            ],
            "severity": "medium",
            "title": "Sensitive Data Logging",
            "description": "Application may log sensitive information",
            "recommendation": "Remove sensitive data from logs in production",
            "cwe_id": "CWE-532",
            "owasp_category": "M9"
        },
        
        # WebView Vulnerabilities
        "webview_js_enabled": {
            "patterns": [
                r'setJavaScriptEnabled\s*\(\s*true\s*\)',
            ],
            "severity": "medium",
            "title": "WebView JavaScript Enabled",
            "description": "WebView has JavaScript enabled which may be exploited",
            "recommendation": "Disable JavaScript if not needed, validate loaded URLs",
            "cwe_id": "CWE-749",
            "owasp_category": "M1"
        },
        
        "webview_file_access": {
            "patterns": [
                r'setAllowFileAccess\s*\(\s*true\s*\)',
                r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
                r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
            ],
            "severity": "high",
            "title": "WebView File Access Enabled",
            "description": "WebView allows file access which may expose local files",
            "recommendation": "Disable file access unless absolutely necessary",
            "cwe_id": "CWE-200",
            "owasp_category": "M1"
        },
        
        "webview_js_interface": {
            "patterns": [
                r'addJavascriptInterface\s*\(',
            ],
            "severity": "high",
            "title": "WebView JavaScript Interface",
            "description": "WebView exposes JavaScript interface which may be exploited on older Android versions",
            "recommendation": "Use @JavascriptInterface annotation and target SDK 17+",
            "cwe_id": "CWE-749",
            "owasp_category": "M1"
        },
        
        # Intent Vulnerabilities
        "implicit_intent": {
            "patterns": [
                r'Intent\s*\(\s*\)\s*;',
                r'new\s+Intent\s*\(\s*[^"\'A-Z]',
            ],
            "severity": "low",
            "title": "Implicit Intent Usage",
            "description": "Implicit intents may be intercepted by malicious apps",
            "recommendation": "Use explicit intents when possible",
            "cwe_id": "CWE-927",
            "owasp_category": "M1"
        },
        
        # SharedPreferences
        "insecure_sharedprefs": {
            "patterns": [
                r'MODE_WORLD_READABLE',
                r'MODE_WORLD_WRITEABLE',
                r'getSharedPreferences\s*\([^)]*,\s*0\s*\)',
            ],
            "severity": "high",
            "title": "Insecure SharedPreferences",
            "description": "SharedPreferences may be accessible to other apps",
            "recommendation": "Use MODE_PRIVATE for SharedPreferences",
            "cwe_id": "CWE-922",
            "owasp_category": "M2"
        },
        
        # External Storage
        "external_storage": {
            "patterns": [
                r'getExternalStorageDirectory\s*\(',
                r'getExternalFilesDir\s*\(',
                r'Environment\.getExternalStoragePublicDirectory',
            ],
            "severity": "medium",
            "title": "External Storage Usage",
            "description": "Data stored on external storage is accessible to other apps",
            "recommendation": "Store sensitive data in internal storage or encrypt it",
            "cwe_id": "CWE-922",
            "owasp_category": "M2"
        },
        
        # Clipboard
        "clipboard_sensitive": {
            "patterns": [
                r'ClipboardManager.*(?i)(password|token|secret)',
                r'setPrimaryClip.*(?i)(password|token|secret)',
            ],
            "severity": "medium",
            "title": "Sensitive Data in Clipboard",
            "description": "Sensitive data may be copied to clipboard",
            "recommendation": "Avoid copying sensitive data to clipboard",
            "cwe_id": "CWE-200",
            "owasp_category": "M9"
        },
        
        # Runtime Exec
        "runtime_exec": {
            "patterns": [
                r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(',
                r'ProcessBuilder\s*\(',
            ],
            "severity": "high",
            "title": "Command Execution",
            "description": "Application executes system commands which may be exploited",
            "recommendation": "Avoid runtime execution, validate all inputs if necessary",
            "cwe_id": "CWE-78",
            "owasp_category": "M7"
        },
        
        # Broadcast
        "unprotected_broadcast": {
            "patterns": [
                r'sendBroadcast\s*\([^,)]*\)',
                r'sendOrderedBroadcast\s*\([^,)]*\)',
            ],
            "severity": "medium",
            "title": "Unprotected Broadcast",
            "description": "Broadcast may be intercepted by other apps",
            "recommendation": "Use LocalBroadcastManager or add permissions",
            "cwe_id": "CWE-927",
            "owasp_category": "M1"
        },
        
        # Temp Files
        "temp_file": {
            "patterns": [
                r'createTempFile\s*\(',
                r'File\.createTempFile\s*\(',
            ],
            "severity": "low",
            "title": "Temporary File Usage",
            "description": "Temporary files may persist and contain sensitive data",
            "recommendation": "Ensure temp files are deleted and contain no sensitive data",
            "cwe_id": "CWE-377",
            "owasp_category": "M2"
        },
        
        # Certificate Pinning Bypass
        "cert_pinning_bypass": {
            "patterns": [
                r'TrustManager.*checkServerTrusted.*return',
                r'HostnameVerifier.*verify.*return\s+true',
                r'SSLSocketFactory.*ALLOW_ALL',
            ],
            "severity": "critical",
            "title": "Certificate Validation Bypass",
            "description": "Certificate validation appears to be disabled",
            "recommendation": "Implement proper certificate validation and pinning",
            "cwe_id": "CWE-295",
            "owasp_category": "M3"
        },
        
        # Path Traversal
        "path_traversal": {
            "patterns": [
                r'new\s+File\s*\([^)]*\+[^)]*\)',
                r'openFileInput\s*\([^)]*\+',
                r'getAssets\s*\(\s*\)\.open\s*\([^)]*\+',
            ],
            "severity": "high",
            "title": "Potential Path Traversal",
            "description": "File path appears to use user input which may allow directory traversal",
            "recommendation": "Validate and sanitize file paths",
            "cwe_id": "CWE-22",
            "owasp_category": "M7"
        },
        
        # Reflection
        "dynamic_loading": {
            "patterns": [
                r'DexClassLoader\s*\(',
                r'PathClassLoader\s*\(',
                r'Class\.forName\s*\([^"\']+\)',
                r'loadClass\s*\([^"\']+\)',
            ],
            "severity": "medium",
            "title": "Dynamic Code Loading",
            "description": "Application loads code dynamically which may be exploited",
            "recommendation": "Verify integrity of dynamically loaded code",
            "cwe_id": "CWE-94",
            "owasp_category": "M7"
        },
    }
    
    # File extensions to analyze
    ANALYZABLE_EXTENSIONS = {'.java', '.kt', '.smali', '.xml', '.json', '.properties'}
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.temp_dir = None
        self.findings: List[Dict[str, Any]] = []
        self.analyzed_files = 0
        self.total_lines = 0
        
    async def analyze(self) -> Dict[str, Any]:
        """Run comprehensive code analysis"""
        try:
            self.temp_dir = tempfile.mkdtemp(prefix="mobai_code_")
            
            # Extract APK
            await self._extract_apk()
            
            # Scan all files
            await self._scan_directory(self.temp_dir)
            
            # Calculate statistics
            stats = self._calculate_stats()
            
            return {
                "code_analysis": {
                    "total_files": stats["total_files"],
                    "total_lines": self.total_lines,
                    "java_files": stats["java_files"],
                    "kotlin_files": stats["kotlin_files"],
                    "smali_files": stats["smali_files"],
                    "findings_summary": stats["findings_summary"],
                    "findings": self.findings
                }
            }
            
        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
    
    async def _extract_apk(self):
        """Extract APK contents"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                z.extractall(self.temp_dir)
        except Exception as e:
            print(f"Error extracting APK: {e}")
    
    async def _scan_directory(self, directory: str):
        """Recursively scan directory for security issues"""
        tasks = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                
                if ext in self.ANALYZABLE_EXTENSIONS:
                    tasks.append(self._analyze_file(file_path))
        
        # Process files in batches to avoid memory issues
        batch_size = 50
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch)
    
    async def _analyze_file(self, file_path: str):
        """Analyze a single file for security issues"""
        try:
            # Determine encoding
            encodings = ['utf-8', 'latin-1', 'ascii']
            content = None
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                return
            
            self.analyzed_files += 1
            lines = content.split('\n')
            self.total_lines += len(lines)
            
            # Get relative path for reporting
            rel_path = os.path.relpath(file_path, self.temp_dir)
            
            # Run all security pattern checks
            for pattern_name, pattern_info in self.SECURITY_PATTERNS.items():
                for pattern in pattern_info["patterns"]:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            self._add_finding(
                                finding_type=pattern_name,
                                severity=pattern_info["severity"],
                                title=pattern_info["title"],
                                description=pattern_info["description"],
                                recommendation=pattern_info.get("recommendation"),
                                file_path=rel_path,
                                line_number=i,
                                code_snippet=line.strip()[:200],
                                cwe_id=pattern_info.get("cwe_id"),
                                owasp_category=pattern_info.get("owasp_category")
                            )
                            break  # One finding per pattern per file
                            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
    
    def _add_finding(self, **kwargs):
        """Add a security finding"""
        # Avoid duplicates
        for existing in self.findings:
            if (existing["type"] == kwargs["finding_type"] and 
                existing["file_path"] == kwargs.get("file_path") and
                existing["line_number"] == kwargs.get("line_number")):
                return
        
        self.findings.append({
            "type": kwargs["finding_type"],
            "severity": kwargs["severity"],
            "title": kwargs["title"],
            "description": kwargs["description"],
            "recommendation": kwargs.get("recommendation"),
            "file_path": kwargs.get("file_path"),
            "line_number": kwargs.get("line_number"),
            "code_snippet": kwargs.get("code_snippet"),
            "cwe_id": kwargs.get("cwe_id"),
            "owasp_category": kwargs.get("owasp_category")
        })
    
    def _calculate_stats(self) -> Dict[str, Any]:
        """Calculate analysis statistics"""
        java_files = 0
        kotlin_files = 0
        smali_files = 0
        
        # Count file types
        if self.temp_dir:
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext == '.java':
                        java_files += 1
                    elif ext == '.kt':
                        kotlin_files += 1
                    elif ext == '.smali':
                        smali_files += 1
        
        # Calculate findings summary
        findings_summary = {
            "total": len(self.findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "by_type": {}
        }
        
        for finding in self.findings:
            severity = finding.get("severity", "info")
            if severity in findings_summary:
                findings_summary[severity] += 1
            
            finding_type = finding.get("type", "unknown")
            if finding_type not in findings_summary["by_type"]:
                findings_summary["by_type"][finding_type] = 0
            findings_summary["by_type"][finding_type] += 1
        
        return {
            "total_files": self.analyzed_files,
            "java_files": java_files,
            "kotlin_files": kotlin_files,
            "smali_files": smali_files,
            "findings_summary": findings_summary
        }
