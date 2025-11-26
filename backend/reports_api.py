"""
Reports API - Pagination-enabled endpoints for report management
Optimized for large datasets (700+ findings)
"""

import os
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Path

from models.database import ReportRepository, FindingRepository
from models.schemas import (
    ReportSummary, ReportDetail, PaginatedFindings, 
    FindingsSummary, AnalysisStatus
)

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/", response_model=List[ReportSummary])
async def get_reports(
    limit: int = Query(50, ge=1, le=100, description="Number of reports to return"),
    offset: int = Query(0, ge=0, description="Number of reports to skip")
):
    """
    Get all reports with pagination.
    Returns summary information only - no findings included.
    """
    reports = await ReportRepository.get_all(limit=limit, offset=offset)
    
    result = []
    for report in reports:
        summary = report.get("findings_summary", {})
        result.append(ReportSummary(
            id=report["id"],
            app_name=report["app_name"],
            package_name=report["package_name"],
            version_name=report.get("version_name"),
            file_name=report["file_name"],
            status=AnalysisStatus(report["status"]),
            risk_score=report.get("risk_score", 0),
            total_findings=summary.get("total", 0),
            critical_findings=summary.get("critical", 0),
            high_findings=summary.get("high", 0),
            created_at=datetime.fromisoformat(report["created_at"]) if isinstance(report["created_at"], str) else report["created_at"],
            completed_at=datetime.fromisoformat(report["completed_at"]) if report.get("completed_at") and isinstance(report["completed_at"], str) else report.get("completed_at")
        ))
    
    return result


@router.get("/{report_id}", response_model=ReportDetail)
async def get_report(
    report_id: int = Path(..., description="Report ID")
):
    """
    Get detailed report by ID.
    
    IMPORTANT: This endpoint does NOT return findings array to prevent
    performance issues with large datasets. Use the /findings endpoint
    with pagination to fetch findings.
    
    Returns:
    - Basic APK information
    - Manifest analysis
    - Certificate analysis
    - Binary analysis
    - Code analysis summary (without findings)
    - Findings summary statistics
    """
    report = await ReportRepository.get_by_id(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Get findings summary from database
    findings_summary = await FindingRepository.get_summary(report_id)
    
    # Build code_analysis without findings array
    code_analysis = report.get("code_analysis", {})
    if code_analysis:
        # Remove findings from code_analysis to reduce payload
        code_analysis.pop("findings", None)
        code_analysis["findings_summary"] = findings_summary
    
    return ReportDetail(
        id=report["id"],
        app_name=report["app_name"],
        package_name=report["package_name"],
        version_name=report.get("version_name"),
        version_code=report.get("version_code"),
        file_name=report["file_name"],
        file_size=report["file_size"],
        md5_hash=report["md5_hash"],
        sha1_hash=report["sha1_hash"],
        sha256_hash=report["sha256_hash"],
        status=AnalysisStatus(report["status"]),
        risk_score=report.get("risk_score", 0),
        created_at=datetime.fromisoformat(report["created_at"]) if isinstance(report["created_at"], str) else report["created_at"],
        completed_at=datetime.fromisoformat(report["completed_at"]) if report.get("completed_at") and isinstance(report["completed_at"], str) else report.get("completed_at"),
        manifest_analysis=report.get("manifest_analysis"),
        certificate_analysis=report.get("certificate_analysis"),
        binary_analysis=report.get("binary_analysis"),
        code_analysis=code_analysis,
        findings_summary=FindingsSummary(**findings_summary)
    )


@router.get("/{report_id}/findings", response_model=PaginatedFindings)
async def get_report_findings(
    report_id: int = Path(..., description="Report ID"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(100, ge=10, le=500, description="Items per page"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    finding_type: Optional[str] = Query(None, alias="type", description="Filter by finding type")
):
    """
    Get paginated findings for a specific report.
    
    This is the PRIMARY endpoint for fetching findings.
    Designed to handle 700+ findings efficiently.
    
    Features:
    - Pagination (default 100 per page)
    - Filter by severity
    - Filter by type
    - Sorted by severity (critical first)
    
    Example usage:
    - GET /api/reports/24/findings?page=1&page_size=100
    - GET /api/reports/24/findings?severity=high
    - GET /api/reports/24/findings?type=sql_injection
    """
    # Verify report exists
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Get paginated findings
    result = await FindingRepository.get_paginated(
        report_id=report_id,
        page=page,
        page_size=page_size,
        severity=severity,
        finding_type=finding_type
    )
    
    return PaginatedFindings(**result)


@router.get("/{report_id}/findings/summary", response_model=FindingsSummary)
async def get_findings_summary(
    report_id: int = Path(..., description="Report ID")
):
    """
    Get only the findings summary statistics for a report.
    Useful for dashboard displays without loading full findings.
    """
    # Verify report exists
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    summary = await FindingRepository.get_summary(report_id)
    return FindingsSummary(**summary)


@router.delete("/{report_id}")
async def delete_report(
    report_id: int = Path(..., description="Report ID")
):
    """Delete a report and all its findings."""
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    await ReportRepository.delete(report_id)
    return {"message": f"Report {report_id} deleted successfully"}
