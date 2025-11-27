"""
Report Comparison Service
Compares two mobile app analysis reports to identify changes
"""

from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime
import json

from models.database import ReportRepository, FindingRepository
from logger import get_logger

logger = get_logger(__name__)


class ReportComparer:
    """Compare two security analysis reports"""

    @staticmethod
    def compare_findings(
        old_findings: List[Dict],
        new_findings: List[Dict]
    ) -> Dict[str, List[Dict]]:
        """
        Compare findings between two reports.

        Returns:
            - new: Findings that appear only in the new report
            - fixed: Findings that were in old but not in new
            - unchanged: Findings present in both
        """
        # Create fingerprints for comparison
        def get_fingerprint(finding: Dict) -> str:
            """Create unique fingerprint for a finding"""
            return f"{finding.get('type', '')}|{finding.get('title', '')}|{finding.get('file_path', '')}|{finding.get('line_number', '')}"

        old_fingerprints = {get_fingerprint(f): f for f in old_findings}
        new_fingerprints = {get_fingerprint(f): f for f in new_findings}

        old_keys = set(old_fingerprints.keys())
        new_keys = set(new_fingerprints.keys())

        # Categorize findings
        new_only = new_keys - old_keys
        fixed = old_keys - new_keys
        unchanged = old_keys & new_keys

        return {
            "new": [new_fingerprints[k] for k in new_only],
            "fixed": [old_fingerprints[k] for k in fixed],
            "unchanged": [new_fingerprints[k] for k in unchanged]
        }

    @staticmethod
    def compare_severity_distribution(
        old_summary: Dict,
        new_summary: Dict
    ) -> Dict[str, Dict]:
        """Compare severity distributions between reports"""
        severities = ["critical", "high", "medium", "low", "info"]

        comparison = {}
        for sev in severities:
            old_count = old_summary.get(sev, 0)
            new_count = new_summary.get(sev, 0)
            diff = new_count - old_count

            comparison[sev] = {
                "old": old_count,
                "new": new_count,
                "difference": diff,
                "change": "increased" if diff > 0 else "decreased" if diff < 0 else "unchanged"
            }

        # Total
        old_total = old_summary.get("total", 0)
        new_total = new_summary.get("total", 0)
        total_diff = new_total - old_total

        comparison["total"] = {
            "old": old_total,
            "new": new_total,
            "difference": total_diff,
            "change": "increased" if total_diff > 0 else "decreased" if total_diff < 0 else "unchanged"
        }

        return comparison

    @staticmethod
    def compare_permissions(
        old_manifest: Dict,
        new_manifest: Dict
    ) -> Dict[str, Any]:
        """Compare permissions between two manifests"""
        old_perms = set()
        new_perms = set()

        for perm in old_manifest.get("permissions", []):
            if isinstance(perm, dict):
                old_perms.add(perm.get("name", ""))
            else:
                old_perms.add(str(perm))

        for perm in new_manifest.get("permissions", []):
            if isinstance(perm, dict):
                new_perms.add(perm.get("name", ""))
            else:
                new_perms.add(str(perm))

        added = new_perms - old_perms
        removed = old_perms - new_perms
        unchanged = old_perms & new_perms

        return {
            "added": list(added),
            "removed": list(removed),
            "unchanged_count": len(unchanged),
            "old_count": len(old_perms),
            "new_count": len(new_perms)
        }

    @staticmethod
    def compare_components(
        old_manifest: Dict,
        new_manifest: Dict
    ) -> Dict[str, Dict]:
        """Compare app components (activities, services, etc.)"""
        component_types = ["activities", "services", "receivers", "providers"]
        comparison = {}

        for comp_type in component_types:
            old_comps = set()
            new_comps = set()

            for comp in old_manifest.get(comp_type, []):
                if isinstance(comp, dict):
                    old_comps.add(comp.get("name", ""))
                else:
                    old_comps.add(str(comp))

            for comp in new_manifest.get(comp_type, []):
                if isinstance(comp, dict):
                    new_comps.add(comp.get("name", ""))
                else:
                    new_comps.add(str(comp))

            added = new_comps - old_comps
            removed = old_comps - new_comps

            comparison[comp_type] = {
                "added": list(added),
                "removed": list(removed),
                "old_count": len(old_comps),
                "new_count": len(new_comps)
            }

        return comparison

    @staticmethod
    def compare_security_flags(
        old_manifest: Dict,
        new_manifest: Dict
    ) -> List[Dict]:
        """Compare security-related flags"""
        flags = [
            ("is_debuggable", "Debuggable", "Risk if enabled"),
            ("allows_backup", "Allows Backup", "Risk if enabled"),
            ("uses_cleartext_traffic", "Cleartext Traffic", "Risk if enabled")
        ]

        changes = []
        for flag_key, flag_name, risk_note in flags:
            old_val = old_manifest.get(flag_key, False)
            new_val = new_manifest.get(flag_key, False)

            if old_val != new_val:
                changes.append({
                    "flag": flag_name,
                    "old_value": old_val,
                    "new_value": new_val,
                    "change_type": "enabled" if new_val else "disabled",
                    "risk_impact": "increased" if new_val else "decreased",
                    "note": risk_note if new_val else "Security improved"
                })

        return changes

    @staticmethod
    def compare_binary_info(
        old_binary: Dict,
        new_binary: Dict
    ) -> Dict[str, Any]:
        """Compare binary analysis results"""
        old_libs = set()
        new_libs = set()

        for lib in old_binary.get("native_libraries", []):
            if isinstance(lib, dict):
                old_libs.add(lib.get("name", ""))
            else:
                old_libs.add(str(lib))

        for lib in new_binary.get("native_libraries", []):
            if isinstance(lib, dict):
                new_libs.add(lib.get("name", ""))
            else:
                new_libs.add(str(lib))

        added_libs = new_libs - old_libs
        removed_libs = old_libs - new_libs

        old_archs = set(old_binary.get("architectures", []))
        new_archs = set(new_binary.get("architectures", []))

        return {
            "size_change": {
                "old": old_binary.get("apk_size", 0),
                "new": new_binary.get("apk_size", 0),
                "difference": new_binary.get("apk_size", 0) - old_binary.get("apk_size", 0)
            },
            "dex_count_change": {
                "old": old_binary.get("dex_count", 0),
                "new": new_binary.get("dex_count", 0)
            },
            "native_libraries": {
                "added": list(added_libs),
                "removed": list(removed_libs)
            },
            "architectures": {
                "added": list(new_archs - old_archs),
                "removed": list(old_archs - new_archs)
            }
        }

    @staticmethod
    def calculate_security_trend(
        old_summary: Dict,
        new_summary: Dict,
        old_risk: int,
        new_risk: int
    ) -> Dict[str, Any]:
        """Calculate overall security trend"""
        # Weight changes by severity
        weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

        old_weighted = sum(old_summary.get(sev, 0) * w for sev, w in weights.items())
        new_weighted = sum(new_summary.get(sev, 0) * w for sev, w in weights.items())

        risk_change = new_risk - old_risk

        # Determine trend
        if risk_change < -10:
            trend = "significantly_improved"
            trend_description = "Security posture has significantly improved"
        elif risk_change < 0:
            trend = "improved"
            trend_description = "Security posture has improved"
        elif risk_change == 0:
            trend = "unchanged"
            trend_description = "Security posture remains the same"
        elif risk_change < 10:
            trend = "degraded"
            trend_description = "Security posture has degraded"
        else:
            trend = "significantly_degraded"
            trend_description = "Security posture has significantly degraded"

        return {
            "trend": trend,
            "description": trend_description,
            "risk_score_change": risk_change,
            "old_risk_score": old_risk,
            "new_risk_score": new_risk,
            "weighted_score_change": new_weighted - old_weighted
        }


async def compare_reports(report_id_1: int, report_id_2: int) -> Dict[str, Any]:
    """
    Compare two reports and return comprehensive comparison.

    Args:
        report_id_1: ID of the older/baseline report
        report_id_2: ID of the newer report to compare

    Returns:
        Detailed comparison results
    """
    # Fetch both reports
    report_1 = await ReportRepository.get_by_id(report_id_1)
    report_2 = await ReportRepository.get_by_id(report_id_2)

    if not report_1:
        raise ValueError(f"Report {report_id_1} not found")
    if not report_2:
        raise ValueError(f"Report {report_id_2} not found")

    # Fetch findings for both
    findings_1_data = await FindingRepository.get_paginated(report_id_1, page=1, page_size=10000)
    findings_2_data = await FindingRepository.get_paginated(report_id_2, page=1, page_size=10000)

    findings_1 = findings_1_data.get("findings", [])
    findings_2 = findings_2_data.get("findings", [])

    # Get summaries
    summary_1 = report_1.get("findings_summary", {})
    summary_2 = report_2.get("findings_summary", {})

    if isinstance(summary_1, str):
        try:
            summary_1 = json.loads(summary_1)
        except:
            summary_1 = {}
    if isinstance(summary_2, str):
        try:
            summary_2 = json.loads(summary_2)
        except:
            summary_2 = {}

    # Get manifests
    manifest_1 = report_1.get("manifest_analysis", {}) or {}
    manifest_2 = report_2.get("manifest_analysis", {}) or {}

    # Get binary info
    binary_1 = report_1.get("binary_analysis", {}) or {}
    binary_2 = report_2.get("binary_analysis", {}) or {}

    comparer = ReportComparer()

    # Build comparison
    comparison = {
        "metadata": {
            "baseline_report": {
                "id": report_id_1,
                "app_name": report_1.get("app_name"),
                "version": report_1.get("version_name"),
                "package_name": report_1.get("package_name"),
                "platform": report_1.get("platform"),
                "analyzed_at": report_1.get("created_at"),
                "risk_score": report_1.get("risk_score", 0)
            },
            "compared_report": {
                "id": report_id_2,
                "app_name": report_2.get("app_name"),
                "version": report_2.get("version_name"),
                "package_name": report_2.get("package_name"),
                "platform": report_2.get("platform"),
                "analyzed_at": report_2.get("created_at"),
                "risk_score": report_2.get("risk_score", 0)
            },
            "comparison_date": datetime.utcnow().isoformat()
        },
        "security_trend": comparer.calculate_security_trend(
            summary_1, summary_2,
            report_1.get("risk_score", 0),
            report_2.get("risk_score", 0)
        ),
        "findings_comparison": comparer.compare_findings(findings_1, findings_2),
        "severity_comparison": comparer.compare_severity_distribution(summary_1, summary_2),
        "permissions_comparison": comparer.compare_permissions(manifest_1, manifest_2),
        "components_comparison": comparer.compare_components(manifest_1, manifest_2),
        "security_flags_comparison": comparer.compare_security_flags(manifest_1, manifest_2),
        "binary_comparison": comparer.compare_binary_info(binary_1, binary_2)
    }

    # Add summary statistics
    findings_comp = comparison["findings_comparison"]
    comparison["summary"] = {
        "new_findings_count": len(findings_comp["new"]),
        "fixed_findings_count": len(findings_comp["fixed"]),
        "unchanged_findings_count": len(findings_comp["unchanged"]),
        "permissions_added": len(comparison["permissions_comparison"]["added"]),
        "permissions_removed": len(comparison["permissions_comparison"]["removed"]),
        "security_flag_changes": len(comparison["security_flags_comparison"]),
        "risk_score_change": comparison["security_trend"]["risk_score_change"]
    }

    logger.info(
        "Report comparison completed",
        extra_data={
            "baseline_id": report_id_1,
            "compared_id": report_id_2,
            "new_findings": len(findings_comp["new"]),
            "fixed_findings": len(findings_comp["fixed"])
        }
    )

    return comparison
