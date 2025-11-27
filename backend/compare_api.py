"""
Report Comparison API Routes
Handles comparing two security analysis reports
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Optional
from pydantic import BaseModel

from compare_service import compare_reports
from models.database import ReportRepository
from auth import get_current_user
from logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/compare", tags=["Report Comparison"])


class CompareRequest(BaseModel):
    baseline_report_id: int
    compared_report_id: int


@router.post("")
async def compare_two_reports(
    request: CompareRequest,
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Compare two reports to identify security changes.

    The baseline_report_id should typically be the older report,
    and compared_report_id should be the newer one.

    Returns detailed comparison including:
    - Security trend (improved/degraded)
    - New findings
    - Fixed findings
    - Permission changes
    - Component changes
    - Security flag changes
    """
    # Validate both reports exist
    report_1 = await ReportRepository.get_by_id(request.baseline_report_id)
    if not report_1:
        raise HTTPException(status_code=404, detail=f"Baseline report {request.baseline_report_id} not found")

    report_2 = await ReportRepository.get_by_id(request.compared_report_id)
    if not report_2:
        raise HTTPException(status_code=404, detail=f"Compared report {request.compared_report_id} not found")

    # Check both are completed
    if report_1["status"] != "completed":
        raise HTTPException(status_code=400, detail="Baseline report analysis not completed")
    if report_2["status"] != "completed":
        raise HTTPException(status_code=400, detail="Compared report analysis not completed")

    # Warn if comparing different apps (but allow it)
    if report_1.get("package_name") != report_2.get("package_name"):
        logger.warning(
            "Comparing reports from different packages",
            extra_data={
                "baseline_package": report_1.get("package_name"),
                "compared_package": report_2.get("package_name")
            }
        )

    try:
        comparison = await compare_reports(
            request.baseline_report_id,
            request.compared_report_id
        )
        return comparison
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Comparison failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Comparison failed")


@router.get("/reports/{report_id}/similar")
async def find_similar_reports(
    report_id: int,
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Find reports for the same app (by package name) for comparison.

    Returns a list of other reports for the same package that can be used
    for version comparison.
    """
    # Get the report
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    package_name = report.get("package_name")
    if not package_name or package_name == "unknown":
        return {"report_id": report_id, "similar_reports": [], "message": "Package name unknown"}

    # Get all reports for this package
    all_reports = await ReportRepository.get_all(limit=100)

    similar = []
    for r in all_reports:
        if r.get("package_name") == package_name and r["id"] != report_id:
            similar.append({
                "id": r["id"],
                "app_name": r.get("app_name"),
                "version_name": r.get("version_name"),
                "status": r.get("status"),
                "risk_score": r.get("risk_score", 0),
                "created_at": r.get("created_at")
            })

    # Sort by date
    similar.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return {
        "report_id": report_id,
        "package_name": package_name,
        "similar_reports": similar
    }


@router.get("/quick")
async def quick_compare(
    baseline_id: int = Query(..., description="Baseline report ID"),
    compared_id: int = Query(..., description="Report ID to compare"),
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Quick comparison returning only summary statistics.

    Lighter weight than full comparison - useful for UI previews.
    """
    report_1 = await ReportRepository.get_by_id(baseline_id)
    report_2 = await ReportRepository.get_by_id(compared_id)

    if not report_1:
        raise HTTPException(status_code=404, detail="Baseline report not found")
    if not report_2:
        raise HTTPException(status_code=404, detail="Compared report not found")

    risk_change = (report_2.get("risk_score", 0) or 0) - (report_1.get("risk_score", 0) or 0)

    # Determine trend
    if risk_change < -10:
        trend = "significantly_improved"
    elif risk_change < 0:
        trend = "improved"
    elif risk_change == 0:
        trend = "unchanged"
    elif risk_change < 10:
        trend = "degraded"
    else:
        trend = "significantly_degraded"

    # Parse summaries
    import json
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

    return {
        "baseline": {
            "id": baseline_id,
            "version": report_1.get("version_name"),
            "risk_score": report_1.get("risk_score", 0),
            "total_findings": summary_1.get("total", 0)
        },
        "compared": {
            "id": compared_id,
            "version": report_2.get("version_name"),
            "risk_score": report_2.get("risk_score", 0),
            "total_findings": summary_2.get("total", 0)
        },
        "risk_score_change": risk_change,
        "findings_change": summary_2.get("total", 0) - summary_1.get("total", 0),
        "trend": trend
    }
