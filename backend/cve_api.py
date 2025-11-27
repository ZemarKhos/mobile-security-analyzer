"""
CVE API Routes
Provides CVE lookup and matching functionality
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Optional, List
from pydantic import BaseModel

from cve_service import CVEDatabase
from models.database import ReportRepository, FindingRepository
from auth import get_current_user, require_analyst
from logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/cve", tags=["CVE Database"])


class CVESearchRequest(BaseModel):
    keyword: str
    limit: int = 20


class CVEMatchResponse(BaseModel):
    finding_id: Optional[int]
    finding_title: Optional[str]
    cve_id: Optional[str]
    cve_description: Optional[str]
    cve_category: Optional[str]
    severity: Optional[str]
    cvss_score: Optional[float]
    match_type: str
    match_confidence: str
    recommendation: Optional[str]
    note: Optional[str]


@router.get("/search")
async def search_cves(
    keyword: str = Query(..., min_length=2, description="Search keyword"),
    limit: int = Query(20, ge=1, le=100, description="Number of results"),
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Search NVD database for CVEs matching keyword.

    Rate limited: 5 requests per minute without API key.
    """
    logger.info(f"CVE search requested", extra_data={"keyword": keyword, "limit": limit})

    results = await CVEDatabase.search_nvd(keyword, limit)

    return {
        "keyword": keyword,
        "count": len(results),
        "results": results
    }


@router.get("/details/{cve_id}")
async def get_cve_details(
    cve_id: str,
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Get detailed information about a specific CVE.

    Results are cached for 24 hours.
    """
    # Validate CVE ID format
    if not cve_id.upper().startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format")

    cve_data = await CVEDatabase.get_cve_details(cve_id.upper())

    if not cve_data:
        raise HTTPException(status_code=404, detail="CVE not found")

    return cve_data


@router.post("/reports/{report_id}/match")
async def match_report_cves(
    report_id: int,
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Automatically match report findings to known CVEs.

    This analyzes all findings and identifies potential CVE matches based on:
    - Known library vulnerabilities
    - Pattern matching against vulnerability categories
    """
    # Get report
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if report["status"] != "completed":
        raise HTTPException(status_code=400, detail="Report analysis not completed")

    # Get all findings
    findings_data = await FindingRepository.get_paginated(report_id, page=1, page_size=10000)
    findings = findings_data.get("findings", [])

    if not findings:
        return {
            "report_id": report_id,
            "matches": [],
            "message": "No findings to analyze"
        }

    # Match findings to CVEs
    platform = report.get("platform", "android")
    matches = await CVEDatabase.match_findings_to_cves(findings, platform)

    # Save matches
    await CVEDatabase.save_report_cves(report_id, matches)

    logger.info(
        "CVE matching completed",
        extra_data={"report_id": report_id, "matches_count": len(matches)}
    )

    return {
        "report_id": report_id,
        "findings_analyzed": len(findings),
        "matches_found": len(matches),
        "matches": matches
    }


@router.get("/reports/{report_id}/matches")
async def get_report_cve_matches(
    report_id: int,
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Get saved CVE matches for a report.
    """
    # Check report exists
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    matches = await CVEDatabase.get_report_cves(report_id)

    # Group by severity
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0
    }

    for match in matches:
        sev = (match.get("severity") or "unknown").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "report_id": report_id,
        "total_matches": len(matches),
        "severity_breakdown": severity_counts,
        "matches": matches
    }


@router.get("/known-libraries")
async def get_known_library_cves(
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Get list of known library CVEs in the database.

    This is a static list of commonly used mobile libraries and their known vulnerabilities.
    """
    libraries = []

    for library, cves in CVEDatabase.KNOWN_LIBRARY_CVES.items():
        libraries.append({
            "library": library,
            "cve_count": len(cves),
            "cves": cves
        })

    return {
        "total_libraries": len(libraries),
        "total_cves": sum(len(cves) for cves in CVEDatabase.KNOWN_LIBRARY_CVES.values()),
        "libraries": libraries
    }


@router.get("/categories")
async def get_cve_categories(
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Get CVE pattern categories used for matching.
    """
    categories = []

    for category, data in CVEDatabase.CVE_PATTERNS.items():
        categories.append({
            "category": category,
            "keywords": data.get("keywords", []),
            "android_cpe": data.get("android_cpe"),
            "ios_cpe": data.get("ios_cpe")
        })

    return {"categories": categories}
