"""
Export API Routes
Handles PDF, CSV, and JSON export of reports
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import Response
from typing import Optional

from models.database import ReportRepository, FindingRepository
from export_service import pdf_exporter, csv_exporter, json_exporter
from auth import require_viewer, get_current_user, AuditLog
from logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/export", tags=["Export"])


@router.get("/reports/{report_id}/pdf")
async def export_report_pdf(
    report_id: int,
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Export report to PDF format.

    Returns a downloadable PDF file containing the full security analysis report.
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

    try:
        pdf_bytes = pdf_exporter.export(report, findings)

        # Log export
        if current_user:
            await AuditLog.log(
                action="report_exported",
                user_id=current_user["id"],
                resource_type="report",
                resource_id=report_id,
                details="PDF export"
            )

        logger.info(
            "Report exported to PDF",
            extra_data={"report_id": report_id, "findings_count": len(findings)}
        )

        filename = f"{report['app_name']}_security_report.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        logger.error(f"PDF export failed: {str(e)}", extra_data={"report_id": report_id})
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


@router.get("/reports/{report_id}/csv")
async def export_findings_csv(
    report_id: int,
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Export findings to CSV format.

    Returns a downloadable CSV file containing all findings.
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

    try:
        csv_bytes = csv_exporter.export_findings(findings)

        if current_user:
            await AuditLog.log(
                action="report_exported",
                user_id=current_user["id"],
                resource_type="report",
                resource_id=report_id,
                details="CSV export"
            )

        logger.info(
            "Findings exported to CSV",
            extra_data={"report_id": report_id, "findings_count": len(findings)}
        )

        filename = f"{report['app_name']}_findings.csv"
        return Response(
            content=csv_bytes,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        logger.error(f"CSV export failed: {str(e)}", extra_data={"report_id": report_id})
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


@router.get("/reports/{report_id}/json")
async def export_report_json(
    report_id: int,
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Export full report to JSON format.

    Returns a downloadable JSON file containing the complete analysis.
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

    try:
        json_bytes = json_exporter.export(report, findings)

        if current_user:
            await AuditLog.log(
                action="report_exported",
                user_id=current_user["id"],
                resource_type="report",
                resource_id=report_id,
                details="JSON export"
            )

        logger.info(
            "Report exported to JSON",
            extra_data={"report_id": report_id, "findings_count": len(findings)}
        )

        filename = f"{report['app_name']}_report.json"
        return Response(
            content=json_bytes,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        logger.error(f"JSON export failed: {str(e)}", extra_data={"report_id": report_id})
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")


@router.get("/reports/{report_id}/summary/csv")
async def export_summary_csv(
    report_id: int,
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Export report summary to CSV format.

    Returns a simplified CSV with just the report metadata and summary.
    """
    # Get report
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        csv_bytes = csv_exporter.export_report_summary(report)

        filename = f"{report['app_name']}_summary.csv"
        return Response(
            content=csv_bytes,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        logger.error(f"Summary CSV export failed: {str(e)}", extra_data={"report_id": report_id})
        raise HTTPException(status_code=500, detail=f"Export failed: {str(e)}")
