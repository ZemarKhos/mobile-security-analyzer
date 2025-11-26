"""
APK Scanner - Core Analysis Engine
Handles APK decompilation and basic static analysis
"""

import os
import re
import hashlib
import zipfile
import tempfile
import shutil
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

# Try to import androguard
try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    print("Warning: Androguard not available. Using fallback methods.")


class APKScanner:
    """Main APK Scanner class for static analysis"""
    
    # Dangerous permission patterns
    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_SMS": "Can read SMS messages",
        "android.permission.SEND_SMS": "Can send SMS messages",
        "android.permission.RECEIVE_SMS": "Can receive SMS messages",
        "android.permission.READ_CONTACTS": "Can read contacts",
        "android.permission.WRITE_CONTACTS": "Can modify contacts",
        "android.permission.READ_CALL_LOG": "Can read call history",
        "android.permission.WRITE_CALL_LOG": "Can modify call history",
        "android.permission.CAMERA": "Can access camera",
        "android.permission.RECORD_AUDIO": "Can record audio",
        "android.permission.ACCESS_FINE_LOCATION": "Can access precise location",
        "android.permission.ACCESS_COARSE_LOCATION": "Can access approximate location",
        "android.permission.READ_EXTERNAL_STORAGE": "Can read external storage",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Can write external storage",
        "android.permission.READ_PHONE_STATE": "Can read phone state",
        "android.permission.CALL_PHONE": "Can make phone calls",
        "android.permission.PROCESS_OUTGOING_CALLS": "Can intercept outgoing calls",
        "android.permission.INTERNET": "Can access internet",
        "android.permission.ACCESS_NETWORK_STATE": "Can access network state",
        "android.permission.BLUETOOTH": "Can access Bluetooth",
        "android.permission.BLUETOOTH_ADMIN": "Can administer Bluetooth",
        "android.permission.NFC": "Can access NFC",
        "android.permission.SYSTEM_ALERT_WINDOW": "Can draw over other apps",
        "android.permission.REQUEST_INSTALL_PACKAGES": "Can request package installation",
    }
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.temp_dir = None
        self.apk = None
        self.findings: List[Dict[str, Any]] = []
        
    async def analyze(self) -> Dict[str, Any]:
        """Run complete analysis on the APK"""
        try:
            # Create temp directory for extraction
            self.temp_dir = tempfile.mkdtemp(prefix="mobai_")
            
            # Calculate hashes first
            hashes = self._calculate_hashes()
            
            # Get basic info
            basic_info = await self._get_basic_info()
            basic_info.update(hashes)
            
            # Run all analysis modules
            manifest_analysis = await self._analyze_manifest()
            certificate_analysis = await self._analyze_certificate()
            binary_analysis = await self._analyze_binary()
            
            # Compile results
            result = {
                "basic_info": basic_info,
                "manifest_analysis": manifest_analysis,
                "certificate_analysis": certificate_analysis,
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
        
        with open(self.apk_path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            "md5_hash": md5.hexdigest(),
            "sha1_hash": sha1.hexdigest(),
            "sha256_hash": sha256.hexdigest()
        }
    
    async def _get_basic_info(self) -> Dict[str, Any]:
        """Extract basic APK information"""
        file_size = os.path.getsize(self.apk_path)
        file_name = os.path.basename(self.apk_path)
        
        info = {
            "file_name": file_name,
            "file_size": file_size,
            "app_name": file_name.replace(".apk", ""),
            "package_name": "unknown",
            "version_name": None,
            "version_code": None
        }
        
        if ANDROGUARD_AVAILABLE:
            try:
                self.apk = APK(self.apk_path)
                info["app_name"] = self.apk.get_app_name() or info["app_name"]
                info["package_name"] = self.apk.get_package() or "unknown"
                info["version_name"] = self.apk.get_androidversion_name()
                info["version_code"] = int(self.apk.get_androidversion_code() or 0)
            except Exception as e:
                print(f"Error parsing APK with androguard: {e}")
        else:
            # Fallback: Try to extract from AndroidManifest.xml
            info = self._extract_basic_info_fallback(info)
        
        return info
    
    def _extract_basic_info_fallback(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback method to extract basic info without androguard"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Extract manifest for parsing
                if "AndroidManifest.xml" in z.namelist():
                    # Note: AndroidManifest.xml is in binary format
                    # Would need AXML parser for full parsing
                    pass
        except Exception as e:
            print(f"Fallback extraction failed: {e}")
        return info
    
    async def _analyze_manifest(self) -> Dict[str, Any]:
        """Analyze AndroidManifest.xml"""
        result = {
            "package_name": "unknown",
            "version_name": None,
            "version_code": None,
            "min_sdk": None,
            "target_sdk": None,
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "is_debuggable": False,
            "allows_backup": True,
            "uses_cleartext_traffic": False,
            "findings": []
        }
        
        if not ANDROGUARD_AVAILABLE or not self.apk:
            return result
        
        try:
            result["package_name"] = self.apk.get_package()
            result["version_name"] = self.apk.get_androidversion_name()
            result["version_code"] = int(self.apk.get_androidversion_code() or 0)
            result["min_sdk"] = int(self.apk.get_min_sdk_version() or 0)
            result["target_sdk"] = int(self.apk.get_target_sdk_version() or 0)
            
            # Analyze permissions
            for perm in self.apk.get_permissions():
                is_dangerous = perm in self.DANGEROUS_PERMISSIONS
                result["permissions"].append({
                    "name": perm,
                    "is_dangerous": is_dangerous,
                    "description": self.DANGEROUS_PERMISSIONS.get(perm, "")
                })
                
                if is_dangerous:
                    self._add_finding(
                        finding_type="dangerous_permission",
                        severity="medium",
                        title=f"Dangerous Permission: {perm.split('.')[-1]}",
                        description=f"App requests dangerous permission: {perm}",
                        recommendation="Verify this permission is necessary for app functionality"
                    )
            
            # Analyze activities
            for activity in self.apk.get_activities():
                exported = self._is_component_exported(activity, "activity")
                result["activities"].append({
                    "name": activity,
                    "exported": exported
                })
                
                if exported and not activity.startswith(result["package_name"]):
                    self._add_finding(
                        finding_type="exported_component",
                        severity="medium",
                        title=f"Exported Activity: {activity.split('.')[-1]}",
                        description=f"Activity {activity} is exported and may be accessible by other apps",
                        recommendation="Review if this activity needs to be exported"
                    )
            
            # Analyze services
            for service in self.apk.get_services():
                exported = self._is_component_exported(service, "service")
                result["services"].append({
                    "name": service,
                    "exported": exported
                })
                
                if exported:
                    self._add_finding(
                        finding_type="exported_service",
                        severity="medium",
                        title=f"Exported Service: {service.split('.')[-1]}",
                        description=f"Service {service} is exported",
                        recommendation="Ensure exported services are properly protected"
                    )
            
            # Analyze receivers
            for receiver in self.apk.get_receivers():
                exported = self._is_component_exported(receiver, "receiver")
                result["receivers"].append({
                    "name": receiver,
                    "exported": exported
                })
            
            # Analyze providers
            for provider in self.apk.get_providers():
                exported = self._is_component_exported(provider, "provider")
                result["providers"].append({
                    "name": provider,
                    "exported": exported
                })
                
                if exported:
                    self._add_finding(
                        finding_type="exported_provider",
                        severity="high",
                        title=f"Exported Content Provider: {provider.split('.')[-1]}",
                        description=f"Content Provider {provider} is exported and may expose sensitive data",
                        recommendation="Review content provider security and add proper permissions"
                    )
            
            # Check for debuggable flag
            if self.apk.is_debuggable():
                result["is_debuggable"] = True
                self._add_finding(
                    finding_type="debuggable_app",
                    severity="high",
                    title="Application is Debuggable",
                    description="The android:debuggable flag is set to true",
                    recommendation="Disable debugging for production builds",
                    cwe_id="CWE-489"
                )
            
            # Check backup flag
            if self.apk.get_attribute_value("application", "allowBackup") != "false":
                result["allows_backup"] = True
                self._add_finding(
                    finding_type="backup_enabled",
                    severity="medium",
                    title="Application Backup Allowed",
                    description="App data can be backed up via ADB",
                    recommendation="Set android:allowBackup to false unless needed",
                    cwe_id="CWE-530"
                )
            
            # Check cleartext traffic
            if self.apk.get_attribute_value("application", "usesCleartextTraffic") == "true":
                result["uses_cleartext_traffic"] = True
                self._add_finding(
                    finding_type="cleartext_traffic",
                    severity="high",
                    title="Cleartext Traffic Allowed",
                    description="Application allows cleartext (unencrypted) network traffic",
                    recommendation="Disable cleartext traffic and use HTTPS",
                    cwe_id="CWE-319"
                )
            
            result["findings"] = [f for f in self.findings if f["type"] in [
                "dangerous_permission", "exported_component", "exported_service",
                "exported_provider", "debuggable_app", "backup_enabled", "cleartext_traffic"
            ]]
            
        except Exception as e:
            print(f"Error analyzing manifest: {e}")
        
        return result
    
    def _is_component_exported(self, component: str, comp_type: str) -> bool:
        """Check if a component is exported"""
        if not self.apk:
            return False
        try:
            # This is a simplified check - actual implementation depends on androguard version
            return True  # Default to true for safety analysis
        except:
            return False
    
    async def _analyze_certificate(self) -> Dict[str, Any]:
        """Analyze APK signing certificate"""
        result = {
            "certificates": [],
            "is_debug_signed": False,
            "is_expired": False,
            "is_self_signed": False,
            "findings": []
        }
        
        if not ANDROGUARD_AVAILABLE or not self.apk:
            return result
        
        try:
            for cert in self.apk.get_certificates():
                cert_info = {
                    "subject": {},
                    "issuer": {},
                    "serial_number": str(cert.serial_number),
                    "valid_from": cert.not_valid_before.isoformat() if hasattr(cert, 'not_valid_before') else None,
                    "valid_until": cert.not_valid_after.isoformat() if hasattr(cert, 'not_valid_after') else None,
                    "signature_algorithm": str(cert.signature_algorithm_oid) if hasattr(cert, 'signature_algorithm_oid') else None
                }
                
                # Extract subject info
                if hasattr(cert, 'subject'):
                    for attr in cert.subject:
                        cert_info["subject"][attr.oid._name] = attr.value
                
                # Extract issuer info
                if hasattr(cert, 'issuer'):
                    for attr in cert.issuer:
                        cert_info["issuer"][attr.oid._name] = attr.value
                
                # Calculate fingerprints
                if hasattr(cert, 'fingerprint'):
                    from cryptography.hazmat.primitives import hashes
                    cert_info["sha256_fingerprint"] = cert.fingerprint(hashes.SHA256()).hex()
                
                result["certificates"].append(cert_info)
                
                # Check for debug certificate
                subject_cn = cert_info["subject"].get("commonName", "").lower()
                if "debug" in subject_cn or "android debug" in subject_cn:
                    result["is_debug_signed"] = True
                    self._add_finding(
                        finding_type="debug_certificate",
                        severity="high",
                        title="Debug Certificate Used",
                        description="Application is signed with a debug certificate",
                        recommendation="Sign the app with a production certificate before release",
                        cwe_id="CWE-295"
                    )
                
                # Check for expired certificate
                if hasattr(cert, 'not_valid_after'):
                    if cert.not_valid_after < datetime.now():
                        result["is_expired"] = True
                        self._add_finding(
                            finding_type="expired_certificate",
                            severity="medium",
                            title="Certificate Expired",
                            description="The signing certificate has expired",
                            recommendation="Re-sign the application with a valid certificate"
                        )
                
                # Check if self-signed
                if cert_info["subject"] == cert_info["issuer"]:
                    result["is_self_signed"] = True
            
            result["findings"] = [f for f in self.findings if f["type"] in [
                "debug_certificate", "expired_certificate"
            ]]
            
        except Exception as e:
            print(f"Error analyzing certificate: {e}")
        
        return result
    
    async def _analyze_binary(self) -> Dict[str, Any]:
        """Analyze APK binary characteristics"""
        result = {
            "apk_size": os.path.getsize(self.apk_path),
            "dex_count": 0,
            "native_libraries": [],
            "architectures": [],
            "protections": [],
            "findings": []
        }
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Count DEX files
                dex_files = [f for f in z.namelist() if f.endswith('.dex')]
                result["dex_count"] = len(dex_files)
                
                # Find native libraries
                lib_files = [f for f in z.namelist() if f.startswith('lib/') and f.endswith('.so')]
                architectures = set()
                
                for lib in lib_files:
                    parts = lib.split('/')
                    if len(parts) >= 3:
                        arch = parts[1]
                        architectures.add(arch)
                        result["native_libraries"].append({
                            "name": parts[-1],
                            "path": lib,
                            "architecture": arch
                        })
                
                result["architectures"] = list(architectures)
                
                # Check for common protections
                # Check for root detection
                if any('root' in f.lower() for f in z.namelist()):
                    result["protections"].append({
                        "name": "Root Detection",
                        "description": "App may include root detection",
                        "is_enabled": True,
                        "severity": "info"
                    })
                
                # Check for native code (potential obfuscation)
                if lib_files:
                    result["protections"].append({
                        "name": "Native Code",
                        "description": "App uses native libraries",
                        "is_enabled": True,
                        "severity": "info"
                    })
                
                # Multi-dex check
                if result["dex_count"] > 1:
                    result["protections"].append({
                        "name": "Multi-DEX",
                        "description": f"App uses {result['dex_count']} DEX files",
                        "is_enabled": True,
                        "severity": "info"
                    })
                
        except Exception as e:
            print(f"Error analyzing binary: {e}")
        
        return result
    
    def _add_finding(self, finding_type: str, severity: str, title: str,
                    description: str, recommendation: str = None,
                    file_path: str = None, line_number: int = None,
                    code_snippet: str = None, cwe_id: str = None,
                    owasp_category: str = None):
        """Add a security finding"""
        self.findings.append({
            "type": finding_type,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "file_path": file_path,
            "line_number": line_number,
            "code_snippet": code_snippet,
            "cwe_id": cwe_id,
            "owasp_category": owasp_category
        })
