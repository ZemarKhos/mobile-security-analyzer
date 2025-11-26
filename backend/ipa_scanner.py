"""
IPA Scanner - iOS Application Analysis Engine
Handles IPA extraction and static analysis for iOS apps
"""

import os
import re
import hashlib
import zipfile
import plistlib
import tempfile
import shutil
from typing import Dict, Any, List, Optional
from datetime import datetime


class IPAScanner:
    """Main IPA Scanner class for iOS static analysis"""
    
    # iOS dangerous permissions/capabilities
    DANGEROUS_CAPABILITIES = {
        "keychain-access-groups": "Accesses Keychain data",
        "application-identifier": "App identifier",
        "aps-environment": "Push notifications enabled",
        "com.apple.developer.associated-domains": "Universal links / App links",
        "com.apple.developer.in-app-payments": "In-app payments",
        "com.apple.developer.healthkit": "HealthKit access",
        "com.apple.developer.homekit": "HomeKit access",
        "com.apple.developer.networking.vpn.api": "VPN configuration",
        "com.apple.developer.nfc.readersession.formats": "NFC access",
        "com.apple.developer.siri": "Siri integration",
        "com.apple.developer.carplay-audio": "CarPlay audio",
        "com.apple.developer.networking.wifi-info": "WiFi info access",
    }
    
    # Privacy-sensitive Info.plist keys
    PRIVACY_KEYS = {
        "NSCameraUsageDescription": "Camera access",
        "NSMicrophoneUsageDescription": "Microphone access",
        "NSPhotoLibraryUsageDescription": "Photo library access",
        "NSPhotoLibraryAddUsageDescription": "Photo library write access",
        "NSLocationWhenInUseUsageDescription": "Location (when in use)",
        "NSLocationAlwaysUsageDescription": "Location (always)",
        "NSLocationAlwaysAndWhenInUseUsageDescription": "Location (always and when in use)",
        "NSContactsUsageDescription": "Contacts access",
        "NSCalendarsUsageDescription": "Calendar access",
        "NSRemindersUsageDescription": "Reminders access",
        "NSBluetoothAlwaysUsageDescription": "Bluetooth access",
        "NSBluetoothPeripheralUsageDescription": "Bluetooth peripheral",
        "NSHealthShareUsageDescription": "HealthKit read",
        "NSHealthUpdateUsageDescription": "HealthKit write",
        "NSMotionUsageDescription": "Motion data access",
        "NSSpeechRecognitionUsageDescription": "Speech recognition",
        "NSFaceIDUsageDescription": "Face ID usage",
        "NSAppleMusicUsageDescription": "Apple Music access",
        "NSHomeKitUsageDescription": "HomeKit access",
        "NSSiriUsageDescription": "Siri access",
        "NFCReaderUsageDescription": "NFC access",
        "NSUserTrackingUsageDescription": "User tracking (ATT)",
    }
    
    # Security patterns for binary/code analysis
    SECURITY_PATTERNS = {
        "insecure_http": {
            "patterns": [
                rb'http://(?!localhost|127\.0\.0\.1)',
                rb'NSAllowsArbitraryLoads.*true',
                rb'NSExceptionAllowsInsecureHTTPLoads',
            ],
            "severity": "high",
            "title": "Insecure HTTP Connection",
            "description": "Application may use unencrypted HTTP connections",
            "recommendation": "Use HTTPS for all network communications",
            "cwe_id": "CWE-319",
            "owasp_category": "M3"
        },
        "hardcoded_secret": {
            "patterns": [
                rb'(?i)(password|passwd|pwd|secret|api_key|apikey)\s*[:=]\s*["\'][^"\']{8,}["\']',
                rb'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
                rb'(?i)Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
            ],
            "severity": "critical",
            "title": "Hardcoded Secret/Credential",
            "description": "Sensitive credential or secret key appears to be hardcoded",
            "recommendation": "Store secrets in Keychain or secure storage",
            "cwe_id": "CWE-798",
            "owasp_category": "M9"
        },
        "weak_crypto": {
            "patterns": [
                rb'(?i)MD5',
                rb'(?i)SHA1(?![0-9])',
                rb'(?i)DES[^3]',
                rb'kCCAlgorithmDES',
                rb'(?i)RC4',
            ],
            "severity": "high",
            "title": "Weak Cryptography",
            "description": "Application uses weak or deprecated cryptographic algorithms",
            "recommendation": "Use modern algorithms like AES-256 and SHA-256",
            "cwe_id": "CWE-327",
            "owasp_category": "M5"
        },
        "jailbreak_detection": {
            "patterns": [
                rb'/Applications/Cydia\.app',
                rb'/Library/MobileSubstrate',
                rb'/bin/bash',
                rb'/usr/sbin/sshd',
                rb'/etc/apt',
                rb'/private/var/lib/apt',
                rb'cydia://',
                rb'isJailbroken',
                rb'jailbreak',
            ],
            "severity": "info",
            "title": "Jailbreak Detection",
            "description": "Application implements jailbreak detection",
            "recommendation": "Jailbreak detection can be bypassed; implement additional security measures",
            "cwe_id": "CWE-919",
            "owasp_category": "M8"
        },
        "ssl_pinning": {
            "patterns": [
                rb'SSLPinningMode',
                rb'pinnedCertificates',
                rb'TrustKit',
                rb'AFSecurityPolicy',
                rb'evaluateServerTrust',
                rb'SecTrustEvaluate',
            ],
            "severity": "info",
            "title": "SSL Pinning Detected",
            "description": "Application implements SSL certificate pinning",
            "recommendation": "Good security practice - ensure pinning is properly implemented",
            "cwe_id": "CWE-295",
            "owasp_category": "M3"
        },
        "clipboard_usage": {
            "patterns": [
                rb'UIPasteboard',
                rb'generalPasteboard',
            ],
            "severity": "medium",
            "title": "Clipboard Usage",
            "description": "Application accesses system clipboard",
            "recommendation": "Avoid storing sensitive data in clipboard",
            "cwe_id": "CWE-200",
            "owasp_category": "M2"
        },
        "keychain_usage": {
            "patterns": [
                rb'SecItemAdd',
                rb'SecItemCopyMatching',
                rb'SecItemUpdate',
                rb'SecItemDelete',
                rb'kSecClass',
            ],
            "severity": "info",
            "title": "Keychain Usage",
            "description": "Application uses iOS Keychain for secure storage",
            "recommendation": "Ensure proper Keychain access control settings",
            "cwe_id": "CWE-922",
            "owasp_category": "M2"
        },
        "logging": {
            "patterns": [
                rb'NSLog\s*\(',
                rb'print\s*\(',
                rb'os_log',
                rb'Logger\.',
            ],
            "severity": "low",
            "title": "Logging Detected",
            "description": "Application uses logging functions",
            "recommendation": "Disable verbose logging in production builds",
            "cwe_id": "CWE-532",
            "owasp_category": "M9"
        },
        "webview": {
            "patterns": [
                rb'UIWebView',
                rb'WKWebView',
                rb'SFSafariViewController',
                rb'javaScriptEnabled',
            ],
            "severity": "medium",
            "title": "WebView Usage",
            "description": "Application uses WebView components",
            "recommendation": "Validate URLs and disable JavaScript if not needed",
            "cwe_id": "CWE-749",
            "owasp_category": "M7"
        },
        "biometric": {
            "patterns": [
                rb'LAContext',
                rb'canEvaluatePolicy',
                rb'evaluatePolicy',
                rb'biometryType',
                rb'deviceOwnerAuthentication',
            ],
            "severity": "info",
            "title": "Biometric Authentication",
            "description": "Application uses biometric authentication (Face ID/Touch ID)",
            "recommendation": "Ensure proper fallback mechanisms are in place",
            "cwe_id": "CWE-287",
            "owasp_category": "M4"
        },
    }
    
    def __init__(self, ipa_path: str):
        self.ipa_path = ipa_path
        self.temp_dir = None
        self.app_dir = None
        self.info_plist = {}
        self.entitlements = {}
        self.findings: List[Dict[str, Any]] = []
        
    async def analyze(self) -> Dict[str, Any]:
        """Run complete analysis on the IPA"""
        try:
            # Create temp directory for extraction
            self.temp_dir = tempfile.mkdtemp(prefix="mobai_ipa_")
            
            # Calculate hashes first
            hashes = self._calculate_hashes()
            
            # Extract IPA
            await self._extract_ipa()
            
            # Get basic info from Info.plist
            basic_info = await self._get_basic_info()
            basic_info.update(hashes)
            
            # Run all analysis modules
            plist_analysis = await self._analyze_plist()
            entitlements_analysis = await self._analyze_entitlements()
            binary_analysis = await self._analyze_binary()
            
            # Compile results
            result = {
                "basic_info": basic_info,
                "manifest_analysis": plist_analysis,  # Using same key for compatibility
                "certificate_analysis": entitlements_analysis,  # Entitlements go here
                "binary_analysis": binary_analysis,
                "findings": self.findings
            }
            
            return result
            
        finally:
            # Cleanup
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
    
    def _calculate_hashes(self) -> Dict[str, str]:
        """Calculate file hashes"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(self.ipa_path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            "md5_hash": md5.hexdigest(),
            "sha1_hash": sha1.hexdigest(),
            "sha256_hash": sha256.hexdigest()
        }
    
    async def _extract_ipa(self):
        """Extract IPA contents"""
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as z:
                z.extractall(self.temp_dir)
            
            # Find the .app directory inside Payload
            payload_dir = os.path.join(self.temp_dir, "Payload")
            if os.path.exists(payload_dir):
                for item in os.listdir(payload_dir):
                    if item.endswith(".app"):
                        self.app_dir = os.path.join(payload_dir, item)
                        break
                        
        except Exception as e:
            print(f"Error extracting IPA: {e}")
            raise
    
    async def _get_basic_info(self) -> Dict[str, Any]:
        """Extract basic IPA information from Info.plist"""
        file_size = os.path.getsize(self.ipa_path)
        file_name = os.path.basename(self.ipa_path)
        
        info = {
            "file_name": file_name,
            "file_size": file_size,
            "platform": "ios",
            "app_name": "Unknown",
            "package_name": "Unknown",
            "version_name": "Unknown",
            "version_code": 0,
            "min_sdk": "Unknown",
            "target_sdk": "Unknown",
        }
        
        # Parse Info.plist
        plist_path = os.path.join(self.app_dir, "Info.plist") if self.app_dir else None
        if plist_path and os.path.exists(plist_path):
            try:
                with open(plist_path, 'rb') as f:
                    self.info_plist = plistlib.load(f)
                
                info["app_name"] = self.info_plist.get("CFBundleDisplayName") or \
                                   self.info_plist.get("CFBundleName", "Unknown")
                info["package_name"] = self.info_plist.get("CFBundleIdentifier", "Unknown")
                info["version_name"] = self.info_plist.get("CFBundleShortVersionString", "Unknown")
                info["version_code"] = int(self.info_plist.get("CFBundleVersion", "0") or "0")
                info["min_sdk"] = self.info_plist.get("MinimumOSVersion", "Unknown")
                info["target_sdk"] = self.info_plist.get("DTPlatformVersion", "Unknown")
                
            except Exception as e:
                print(f"Error parsing Info.plist: {e}")
        
        return info
    
    async def _analyze_plist(self) -> Dict[str, Any]:
        """Analyze Info.plist for security/privacy settings"""
        analysis = {
            "privacy_permissions": [],
            "url_schemes": [],
            "ats_settings": {},
            "exported_activities": [],  # URL schemes can be exploited
        }
        
        # Check privacy permissions
        for key, description in self.PRIVACY_KEYS.items():
            if key in self.info_plist:
                usage_desc = self.info_plist.get(key, "")
                analysis["privacy_permissions"].append({
                    "key": key,
                    "description": description,
                    "usage_description": usage_desc
                })
                
                self.findings.append({
                    "type": "privacy_permission",
                    "severity": "info",
                    "title": f"Privacy Permission: {description}",
                    "description": f"App requests {description}. Usage: {usage_desc}",
                    "file_path": "Info.plist",
                    "recommendation": "Ensure permission is necessary and properly explained",
                    "cwe_id": "CWE-250",
                    "owasp_category": "M1"
                })
        
        # Check URL schemes
        url_types = self.info_plist.get("CFBundleURLTypes", [])
        for url_type in url_types:
            schemes = url_type.get("CFBundleURLSchemes", [])
            for scheme in schemes:
                analysis["url_schemes"].append(scheme)
                self.findings.append({
                    "type": "url_scheme",
                    "severity": "low",
                    "title": f"URL Scheme: {scheme}",
                    "description": f"App registers custom URL scheme: {scheme}://",
                    "file_path": "Info.plist",
                    "recommendation": "Validate all input from URL scheme handlers",
                    "cwe_id": "CWE-939",
                    "owasp_category": "M1"
                })
        
        # Check App Transport Security
        ats = self.info_plist.get("NSAppTransportSecurity", {})
        analysis["ats_settings"] = ats
        
        if ats.get("NSAllowsArbitraryLoads", False):
            self.findings.append({
                "type": "insecure_transport",
                "severity": "high",
                "title": "ATS Disabled - Arbitrary Loads Allowed",
                "description": "App Transport Security allows arbitrary HTTP loads",
                "file_path": "Info.plist",
                "recommendation": "Enable ATS and use HTTPS for all connections",
                "cwe_id": "CWE-319",
                "owasp_category": "M3"
            })
        
        if ats.get("NSAllowsArbitraryLoadsForMedia", False):
            self.findings.append({
                "type": "insecure_transport",
                "severity": "medium",
                "title": "ATS Disabled for Media",
                "description": "App Transport Security allows arbitrary loads for media",
                "file_path": "Info.plist",
                "recommendation": "Consider using HTTPS for media content",
                "cwe_id": "CWE-319",
                "owasp_category": "M3"
            })
        
        # Check for exception domains
        exception_domains = ats.get("NSExceptionDomains", {})
        for domain, settings in exception_domains.items():
            if settings.get("NSExceptionAllowsInsecureHTTPLoads", False):
                self.findings.append({
                    "type": "insecure_transport",
                    "severity": "medium",
                    "title": f"ATS Exception: {domain}",
                    "description": f"HTTP allowed for domain: {domain}",
                    "file_path": "Info.plist",
                    "recommendation": f"Use HTTPS for {domain}",
                    "cwe_id": "CWE-319",
                    "owasp_category": "M3"
                })
        
        return analysis
    
    async def _analyze_entitlements(self) -> Dict[str, Any]:
        """Analyze app entitlements"""
        analysis = {
            "entitlements": [],
            "capabilities": [],
            "signing_info": {}
        }
        
        # Try to find embedded.mobileprovision
        if self.app_dir:
            provision_path = os.path.join(self.app_dir, "embedded.mobileprovision")
            if os.path.exists(provision_path):
                try:
                    with open(provision_path, 'rb') as f:
                        content = f.read()
                    
                    # Extract plist from provision file
                    start = content.find(b'<?xml')
                    end = content.find(b'</plist>') + 8
                    if start != -1 and end > start:
                        plist_data = content[start:end]
                        provision = plistlib.loads(plist_data)
                        
                        self.entitlements = provision.get("Entitlements", {})
                        
                        analysis["signing_info"] = {
                            "team_name": provision.get("TeamName", "Unknown"),
                            "app_id_name": provision.get("AppIDName", "Unknown"),
                            "creation_date": str(provision.get("CreationDate", "")),
                            "expiration_date": str(provision.get("ExpirationDate", "")),
                        }
                        
                except Exception as e:
                    print(f"Error parsing provisioning profile: {e}")
        
        # Analyze entitlements
        for key, value in self.entitlements.items():
            capability_desc = self.DANGEROUS_CAPABILITIES.get(key, f"Custom capability: {key}")
            analysis["entitlements"].append({
                "key": key,
                "value": str(value),
                "description": capability_desc
            })
            
            # Flag certain capabilities as findings
            if key in ["com.apple.developer.networking.vpn.api", 
                      "com.apple.developer.healthkit",
                      "keychain-access-groups"]:
                self.findings.append({
                    "type": "capability",
                    "severity": "info",
                    "title": f"Capability: {capability_desc}",
                    "description": f"App has capability: {key}",
                    "file_path": "embedded.mobileprovision",
                    "recommendation": "Ensure capability is necessary",
                    "cwe_id": "CWE-250",
                    "owasp_category": "M1"
                })
        
        return analysis
    
    async def _analyze_binary(self) -> Dict[str, Any]:
        """Analyze binary and resources for security issues"""
        analysis = {
            "architectures": [],
            "frameworks": [],
            "libraries": [],
            "encryption_info": {},
            "pie_enabled": False,
            "arc_enabled": False,
            "stack_canary": False,
        }
        
        if not self.app_dir:
            return analysis
        
        # Find main binary
        app_name = os.path.basename(self.app_dir).replace(".app", "")
        binary_path = os.path.join(self.app_dir, app_name)
        
        if os.path.exists(binary_path):
            await self._scan_binary_patterns(binary_path)
            
            # Check binary properties using otool if available
            try:
                import subprocess
                result = subprocess.run(
                    ["otool", "-hv", binary_path],
                    capture_output=True, text=True, timeout=30
                )
                if "PIE" in result.stdout:
                    analysis["pie_enabled"] = True
                    
                # Get architectures
                result = subprocess.run(
                    ["lipo", "-info", binary_path],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    arch_match = re.search(r': (.+)$', result.stdout)
                    if arch_match:
                        analysis["architectures"] = arch_match.group(1).strip().split()
                        
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        
        # Scan frameworks
        frameworks_dir = os.path.join(self.app_dir, "Frameworks")
        if os.path.exists(frameworks_dir):
            for item in os.listdir(frameworks_dir):
                if item.endswith(".framework"):
                    analysis["frameworks"].append(item.replace(".framework", ""))
                elif item.endswith(".dylib"):
                    analysis["libraries"].append(item)
        
        # Scan all files for patterns
        await self._scan_all_files()
        
        return analysis
    
    async def _scan_binary_patterns(self, binary_path: str):
        """Scan binary file for security patterns"""
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            for pattern_type, pattern_info in self.SECURITY_PATTERNS.items():
                for pattern in pattern_info["patterns"]:
                    matches = list(re.finditer(pattern, content))
                    if matches:
                        self.findings.append({
                            "type": pattern_type,
                            "severity": pattern_info["severity"],
                            "title": pattern_info["title"],
                            "description": pattern_info["description"],
                            "file_path": os.path.basename(binary_path),
                            "recommendation": pattern_info["recommendation"],
                            "cwe_id": pattern_info["cwe_id"],
                            "owasp_category": pattern_info["owasp_category"],
                            "match_count": len(matches)
                        })
                        break  # One finding per pattern type per file
                        
        except Exception as e:
            print(f"Error scanning binary: {e}")
    
    async def _scan_all_files(self):
        """Scan all extracted files for patterns"""
        if not self.app_dir:
            return
            
        for root, _, files in os.walk(self.app_dir):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip very large files
                try:
                    if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB
                        continue
                except:
                    continue
                
                # Scan plist files for sensitive data
                if file.endswith(".plist"):
                    await self._scan_plist_file(file_path)
                
                # Scan strings files
                elif file.endswith(".strings"):
                    await self._scan_strings_file(file_path)
    
    async def _scan_plist_file(self, file_path: str):
        """Scan plist file for sensitive data"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for hardcoded URLs
            urls = re.findall(rb'https?://[^\s<>"]+', content)
            for url in urls[:5]:  # Limit to first 5
                url_str = url.decode('utf-8', errors='ignore')
                if 'http://' in url_str and 'localhost' not in url_str:
                    rel_path = os.path.relpath(file_path, self.app_dir)
                    self.findings.append({
                        "type": "insecure_http",
                        "severity": "medium",
                        "title": "HTTP URL in Plist",
                        "description": f"Found HTTP URL: {url_str[:100]}",
                        "file_path": rel_path,
                        "recommendation": "Use HTTPS instead of HTTP",
                        "cwe_id": "CWE-319",
                        "owasp_category": "M3"
                    })
                    break
                    
        except Exception as e:
            pass
    
    async def _scan_strings_file(self, file_path: str):
        """Scan .strings file for sensitive data"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for potential secrets
            if re.search(rb'(?i)(api_key|secret|password|token)\s*=', content):
                rel_path = os.path.relpath(file_path, self.app_dir)
                self.findings.append({
                    "type": "potential_secret",
                    "severity": "medium",
                    "title": "Potential Secret in Strings File",
                    "description": f"Found potential secret reference in {os.path.basename(file_path)}",
                    "file_path": rel_path,
                    "recommendation": "Review and remove any hardcoded secrets",
                    "cwe_id": "CWE-798",
                    "owasp_category": "M9"
                })
                
        except Exception as e:
            pass


async def analyze_ipa(ipa_path: str) -> Dict[str, Any]:
    """Convenience function to analyze an IPA file"""
    scanner = IPAScanner(ipa_path)
    return await scanner.analyze()
