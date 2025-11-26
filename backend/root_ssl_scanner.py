"""
Root Detection & SSL Pinning Scanner
Scans decompiled APK/IPA for root detection and SSL pinning implementations.
Uses patterns from database (configurable by user).
"""

import os
import re
import subprocess
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class SecurityMechanismFinding:
    """Represents a detected security mechanism (root detection or SSL pinning)"""
    type: str  # 'root_detection', 'ssl_pinning', 'anti_tampering', etc.
    category: str  # Sub-category like 'RootBeer', 'TrustManager', etc.
    file_path: str
    line_number: int
    code_snippet: str
    pattern_matched: str
    severity: str = "info"
    description: str = ""
    bypass_difficulty: str = "medium"  # easy, medium, hard


class RootSSLScanner:
    """Scanner for Root Detection and SSL Pinning mechanisms in Android/iOS apps"""
    
    # Fallback patterns if database is empty
    FALLBACK_ROOT_PATTERNS = {
        "RootBeer": {
            "patterns": [re.compile(r"RootBeer", re.IGNORECASE)],
            "description": "RootBeer library detection",
            "bypass_difficulty": "medium"
        },
        "SuBinary": {
            "patterns": [re.compile(r"/system/xbin/su"), re.compile(r"/system/bin/su")],
            "description": "Su binary path detection",
            "bypass_difficulty": "easy"
        },
        "Magisk": {
            "patterns": [re.compile(r"com\.topjohnwu\.magisk", re.IGNORECASE)],
            "description": "Magisk detection",
            "bypass_difficulty": "medium"
        },
    }
    
    FALLBACK_SSL_PATTERNS = {
        "TrustManager": {
            "patterns": [re.compile(r"X509TrustManager", re.IGNORECASE)],
            "description": "Custom TrustManager implementation",
            "bypass_difficulty": "medium"
        },
        "CertificatePinner": {
            "patterns": [re.compile(r"CertificatePinner", re.IGNORECASE)],
            "description": "OkHttp CertificatePinner",
            "bypass_difficulty": "medium"
        },
    }

    def __init__(self, decompiled_dir: str, rules: Optional[List[Dict]] = None):
        """
        Initialize scanner with decompiled APK directory
        
        Args:
            decompiled_dir: Path to decompiled APK
            rules: List of rule dicts from database (optional, will use fallback if None)
        """
        self.decompiled_dir = decompiled_dir
        self.findings: List[SecurityMechanismFinding] = []
        self.rules = rules or []
        
        # Compile rules into pattern groups
        self._compile_rules()
        
    def _compile_rules(self):
        """Compile database rules into regex patterns"""
        self.root_detection_patterns = {}
        self.ssl_pinning_patterns = {}
        self.anti_tampering_patterns = {}
        self.ios_jailbreak_patterns = {}
        self.ios_ssl_patterns = {}
        
        for rule in self.rules:
            if not rule.get("is_enabled", True):
                continue
                
            category = rule.get("category", "Unknown")
            pattern_str = rule.get("pattern", "")
            is_regex = rule.get("is_regex", True)
            case_sensitive = rule.get("case_sensitive", False)
            
            try:
                if is_regex:
                    flags = 0 if case_sensitive else re.IGNORECASE
                    compiled_pattern = re.compile(pattern_str, flags)
                else:
                    # Plain text search - escape and compile
                    flags = 0 if case_sensitive else re.IGNORECASE
                    compiled_pattern = re.compile(re.escape(pattern_str), flags)
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern_str}': {e}")
                continue
            
            rule_info = {
                "pattern": compiled_pattern,
                "description": rule.get("description", ""),
                "bypass_difficulty": rule.get("bypass_difficulty", "medium"),
                "severity": rule.get("severity", "info"),
                "name": rule.get("name", "Unknown"),
            }
            
            rule_type = rule.get("type", "")
            
            if rule_type == "root_detection":
                if category not in self.root_detection_patterns:
                    self.root_detection_patterns[category] = []
                self.root_detection_patterns[category].append(rule_info)
                
            elif rule_type == "ssl_pinning":
                if category not in self.ssl_pinning_patterns:
                    self.ssl_pinning_patterns[category] = []
                self.ssl_pinning_patterns[category].append(rule_info)
                
            elif rule_type == "anti_tampering":
                if category not in self.anti_tampering_patterns:
                    self.anti_tampering_patterns[category] = []
                self.anti_tampering_patterns[category].append(rule_info)
                
            elif rule_type == "ios_jailbreak":
                if category not in self.ios_jailbreak_patterns:
                    self.ios_jailbreak_patterns[category] = []
                self.ios_jailbreak_patterns[category].append(rule_info)
                
            elif rule_type == "ios_ssl_pinning":
                if category not in self.ios_ssl_patterns:
                    self.ios_ssl_patterns[category] = []
                self.ios_ssl_patterns[category].append(rule_info)
        
        # Use fallbacks if no rules loaded
        if not self.root_detection_patterns:
            logger.info("Using fallback root detection patterns")
            for cat, config in self.FALLBACK_ROOT_PATTERNS.items():
                self.root_detection_patterns[cat] = [{
                    "pattern": p,
                    "description": config["description"],
                    "bypass_difficulty": config["bypass_difficulty"],
                    "severity": "info",
                    "name": cat,
                } for p in config["patterns"]]
                
        if not self.ssl_pinning_patterns:
            logger.info("Using fallback SSL pinning patterns")
            for cat, config in self.FALLBACK_SSL_PATTERNS.items():
                self.ssl_pinning_patterns[cat] = [{
                    "pattern": p,
                    "description": config["description"],
                    "bypass_difficulty": config["bypass_difficulty"],
                    "severity": "info",
                    "name": cat,
                } for p in config["patterns"]]
        
    def scan_all(self) -> Dict[str, Any]:
        """Run all scans and return comprehensive results"""
        self.findings = []
        
        # Scan Java/Smali files
        self._scan_source_files()
        
        # Scan native libraries
        self._scan_native_files()
        
        # Scan XML configs (Network Security Config)
        self._scan_xml_configs()
        
        return self._generate_report()
    
    def _scan_source_files(self):
        """Scan Java and Smali files for root detection and SSL pinning"""
        extensions = ('.java', '.smali', '.kt', '.swift', '.m', '.h')
        
        for root, _, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(extensions):
                    file_path = os.path.join(root, file)
                    self._scan_file(file_path)
    
    def _scan_file(self, file_path: str):
        """Scan a single source file for patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, start=1):
                # Check root detection patterns
                for category, rules in self.root_detection_patterns.items():
                    for rule_info in rules:
                        pattern = rule_info["pattern"]
                        if pattern.search(line):
                            # Get context (surrounding lines)
                            start = max(0, line_num - 3)
                            end = min(len(lines), line_num + 2)
                            context = ''.join(lines[start:end])
                            
                            finding = SecurityMechanismFinding(
                                type="root_detection",
                                category=category,
                                file_path=os.path.relpath(file_path, self.decompiled_dir),
                                line_number=line_num,
                                code_snippet=context.strip()[:500],
                                pattern_matched=pattern.pattern,
                                description=rule_info["description"],
                                bypass_difficulty=rule_info["bypass_difficulty"],
                                severity=rule_info.get("severity", "info")
                            )
                            self.findings.append(finding)
                            break
                
                # Check SSL pinning patterns
                for category, rules in self.ssl_pinning_patterns.items():
                    for rule_info in rules:
                        pattern = rule_info["pattern"]
                        if pattern.search(line):
                            start = max(0, line_num - 3)
                            end = min(len(lines), line_num + 2)
                            context = ''.join(lines[start:end])
                            
                            finding = SecurityMechanismFinding(
                                type="ssl_pinning",
                                category=category,
                                file_path=os.path.relpath(file_path, self.decompiled_dir),
                                line_number=line_num,
                                code_snippet=context.strip()[:500],
                                pattern_matched=pattern.pattern,
                                description=rule_info["description"],
                                bypass_difficulty=rule_info["bypass_difficulty"],
                                severity=rule_info.get("severity", "info")
                            )
                            self.findings.append(finding)
                            break
                
                # Check anti-tampering patterns
                for category, rules in self.anti_tampering_patterns.items():
                    for rule_info in rules:
                        pattern = rule_info["pattern"]
                        if pattern.search(line):
                            start = max(0, line_num - 3)
                            end = min(len(lines), line_num + 2)
                            context = ''.join(lines[start:end])
                            
                            finding = SecurityMechanismFinding(
                                type="anti_tampering",
                                category=category,
                                file_path=os.path.relpath(file_path, self.decompiled_dir),
                                line_number=line_num,
                                code_snippet=context.strip()[:500],
                                pattern_matched=pattern.pattern,
                                description=rule_info["description"],
                                bypass_difficulty=rule_info["bypass_difficulty"],
                                severity=rule_info.get("severity", "info")
                            )
                            self.findings.append(finding)
                            break
                            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
    
    def _scan_native_files(self):
        """Scan native .so/.dylib libraries using strings command"""
        lib_dirs = [
            os.path.join(self.decompiled_dir, "lib"),
            os.path.join(self.decompiled_dir, "Frameworks"),
        ]
        
        for lib_dir in lib_dirs:
            if not os.path.isdir(lib_dir):
                continue
                
            for root, _, files in os.walk(lib_dir):
                for file in files:
                    if file.endswith(('.so', '.dylib')):
                        file_path = os.path.join(root, file)
                        self._scan_native_file(file_path)
    
    def _scan_native_file(self, file_path: str):
        """Scan a single native library file"""
        try:
            result = subprocess.run(
                ["strings", file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return
                
            strings_output = result.stdout.splitlines()
            
            # Combine all patterns for native scanning
            all_patterns = {}
            all_patterns.update(self.root_detection_patterns)
            all_patterns.update(self.ssl_pinning_patterns)
            all_patterns.update(self.anti_tampering_patterns)
            
            for line_num, line in enumerate(strings_output, start=1):
                for category, rules in all_patterns.items():
                    for rule_info in rules:
                        pattern = rule_info["pattern"]
                        if pattern.search(line):
                            finding = SecurityMechanismFinding(
                                type="native_protection",
                                category=category,
                                file_path=os.path.relpath(file_path, self.decompiled_dir),
                                line_number=line_num,
                                code_snippet=line.strip()[:200],
                                pattern_matched=pattern.pattern,
                                description=rule_info["description"],
                                bypass_difficulty="hard",  # Native is always harder
                                severity="high"
                            )
                            self.findings.append(finding)
                            break
                            
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout scanning native file: {file_path}")
        except Exception as e:
            logger.error(f"Error scanning native file {file_path}: {e}")
    
    def _scan_xml_configs(self):
        """Scan XML configuration files for network security config"""
        xml_paths = [
            os.path.join(self.decompiled_dir, "res", "xml"),
            os.path.join(self.decompiled_dir, "res", "raw"),
        ]
        
        for xml_dir in xml_paths:
            if not os.path.isdir(xml_dir):
                continue
                
            for file in os.listdir(xml_dir):
                if file.endswith('.xml'):
                    file_path = os.path.join(xml_dir, file)
                    self._scan_xml_file(file_path)
    
    def _scan_xml_file(self, file_path: str):
        """Scan XML file for network security configuration"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Check for network security config patterns
            nsc_patterns = [
                (r'<pin-set', 'Certificate pinning in Network Security Config'),
                (r'<trust-anchors', 'Custom trust anchors defined'),
                (r'cleartextTrafficPermitted\s*=\s*["\']false["\']', 'Cleartext traffic disabled'),
                (r'<certificates\s+src\s*=\s*["\']@raw/', 'Custom certificates embedded'),
            ]
            
            for pattern, description in nsc_patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    finding = SecurityMechanismFinding(
                        type="ssl_pinning",
                        category="NetworkSecurityConfig",
                        file_path=os.path.relpath(file_path, self.decompiled_dir),
                        line_number=line_num,
                        code_snippet=match.group()[:200],
                        pattern_matched=pattern,
                        description=description,
                        bypass_difficulty="easy"
                    )
                    self.findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error scanning XML file {file_path}: {e}")
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive scan report"""
        # Deduplicate findings (same file + line + category)
        unique_findings = {}
        for f in self.findings:
            key = f"{f.file_path}:{f.line_number}:{f.category}"
            if key not in unique_findings:
                unique_findings[key] = f
        
        findings_list = list(unique_findings.values())
        
        # Categorize findings
        root_detection_findings = [f for f in findings_list if f.type == "root_detection"]
        ssl_pinning_findings = [f for f in findings_list if f.type == "ssl_pinning"]
        native_findings = [f for f in findings_list if f.type == "native_protection"]
        anti_tampering_findings = [f for f in findings_list if f.type == "anti_tampering"]
        
        # Count by category
        root_categories = {}
        for f in root_detection_findings:
            root_categories[f.category] = root_categories.get(f.category, 0) + 1
            
        ssl_categories = {}
        for f in ssl_pinning_findings:
            ssl_categories[f.category] = ssl_categories.get(f.category, 0) + 1
        
        # Determine overall bypass difficulty
        difficulties = [f.bypass_difficulty for f in findings_list]
        if "hard" in difficulties:
            overall_difficulty = "hard"
        elif "medium" in difficulties:
            overall_difficulty = "medium"
        elif difficulties:
            overall_difficulty = "easy"
        else:
            overall_difficulty = "none"
        
        return {
            "summary": {
                "total_findings": len(findings_list),
                "root_detection_count": len(root_detection_findings),
                "ssl_pinning_count": len(ssl_pinning_findings),
                "native_protection_count": len(native_findings),
                "anti_tampering_count": len(anti_tampering_findings),
                "overall_bypass_difficulty": overall_difficulty,
                "root_detection_categories": root_categories,
                "ssl_pinning_categories": ssl_categories,
            },
            "root_detection": [asdict(f) for f in root_detection_findings],
            "ssl_pinning": [asdict(f) for f in ssl_pinning_findings],
            "native_protection": [asdict(f) for f in native_findings],
            "anti_tampering": [asdict(f) for f in anti_tampering_findings],
            "all_findings": [asdict(f) for f in findings_list],
        }


async def get_rules_from_database(platform: str = "android") -> List[Dict]:
    """
    Fetch enabled rules from database for a specific platform.
    
    Args:
        platform: 'android' or 'ios'
        
    Returns:
        List of rule dictionaries
    """
    try:
        from models.database import SecurityRulesRepository
        rules = await SecurityRulesRepository.get_all(
            platform=platform,
            enabled_only=True
        )
        return rules
    except Exception as e:
        logger.error(f"Failed to fetch rules from database: {e}")
        return []


def scan_for_security_mechanisms(decompiled_dir: str, rules: Optional[List[Dict]] = None) -> Dict[str, Any]:
    """
    Main entry point for scanning an APK for root detection and SSL pinning.
    
    Args:
        decompiled_dir: Path to decompiled APK directory
        rules: Optional list of rules from database
        
    Returns:
        Dict containing scan results
    """
    scanner = RootSSLScanner(decompiled_dir, rules=rules)
    return scanner.scan_all()


async def scan_for_security_mechanisms_async(decompiled_dir: str, platform: str = "android") -> Dict[str, Any]:
    """
    Async version that fetches rules from database first.
    
    Args:
        decompiled_dir: Path to decompiled APK/IPA directory
        platform: 'android' or 'ios'
        
    Returns:
        Dict containing scan results
    """
    rules = await get_rules_from_database(platform)
    scanner = RootSSLScanner(decompiled_dir, rules=rules)
    return scanner.scan_all()
