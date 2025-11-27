"""
Mobile Analyzer - FastAPI Backend
Main application entry point
"""

import os
import hashlib
import time
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from models.database import init_database, ReportRepository, FindingRepository
from models.schemas import UploadResponse, HealthResponse, AnalysisStatus, Platform
from scanner import APKScanner
from advanced_scanner import AdvancedScanner
from ipa_scanner import IPAScanner
from reports_api import router as reports_router
from ai_api import router as ai_router
from rules_api import router as rules_router
from auth_api import router as auth_router
from export_api import router as export_router
from cve_api import router as cve_router
from compare_api import router as compare_router
from dast_api import router as dast_router
from auth import UserRepository, get_current_user, AuditLog
from cve_service import CVEDatabase
from logger import get_logger, AnalysisLogger, RequestLoggingMiddleware, setup_logging

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Configuration
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
DATA_DIR = os.getenv("DATA_DIR", "/app/data")
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", 200 * 1024 * 1024))  # 200MB default
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",")

# Supported file types
SUPPORTED_EXTENSIONS = {'.apk', '.ipa'}

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    logger.info("Starting Mobile Analyzer...")

    # Ensure directories exist
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    # Initialize database
    await init_database()

    # Initialize auth tables
    await UserRepository.init_table()

    # Initialize CVE tables
    await CVEDatabase.init_table()

    logger.info("Mobile Analyzer started successfully!", extra_data={
        "upload_dir": UPLOAD_DIR,
        "data_dir": DATA_DIR,
        "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024)
    })
    yield

    # Shutdown
    logger.info("Shutting down Mobile Analyzer...")


# Create FastAPI app
app = FastAPI(
    title="MobAI - Mobile Security Analyzer",
    description="Android APK & iOS IPA Security Analysis Tool with Advanced DAST/Frida Capabilities",
    version="2.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Request logging middleware
app.add_middleware(RequestLoggingMiddleware)

# CORS middleware for frontend - properly configured for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    expose_headers=["Content-Disposition"],
    max_age=600
)

# Include routers
app.include_router(auth_router)
app.include_router(reports_router)
app.include_router(ai_router)
app.include_router(rules_router)
app.include_router(export_router)
app.include_router(cve_router)
app.include_router(compare_router)
app.include_router(dast_router)


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version="2.1.0",
        timestamp=datetime.utcnow()
    )


@app.get("/api/config")
async def get_config():
    """Get public configuration"""
    return {
        "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024),
        "supported_formats": list(SUPPORTED_EXTENSIONS),
        "version": "2.1.0",
        "features": {
            "authentication": True,
            "pdf_export": True,
            "csv_export": True,
            "cve_matching": True,
            "report_comparison": True,
            "ai_integration": True,
            "dast_frida": True,
            "ultimate_bypass": True,
            "flutter_bypass": True,
            "traffic_interception": True
        }
    }


@app.post("/api/upload", response_model=UploadResponse)
@limiter.limit("10/minute")
async def upload_app(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="APK or IPA file to analyze"),
    current_user: Optional[dict] = Depends(get_current_user)
):
    """
    Upload an APK or IPA file for analysis.

    The file is saved and analysis is started in the background.
    Returns immediately with a report ID to track progress.

    Supported formats:
    - .apk (Android)
    - .ipa (iOS)

    Rate limited: 10 uploads per minute
    """
    # Validate file extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    file_ext = os.path.splitext(file.filename.lower())[1]
    if file_ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Supported formats: {', '.join(SUPPORTED_EXTENSIONS)}"
        )

    # Check file size
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)

    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
        )

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file not allowed")

    # Sanitize filename - remove path traversal attempts
    safe_basename = os.path.basename(file.filename)
    safe_basename = "".join(c for c in safe_basename if c.isalnum() or c in '._-')

    # Generate unique filename with hash
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()[:16]
    safe_filename = f"{file_hash}_{safe_basename}"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)

    # Save file
    with open(file_path, "wb") as f:
        f.write(content)

    # Calculate hashes
    md5_hash = hashlib.md5(content).hexdigest()
    sha1_hash = hashlib.sha1(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()

    # Determine platform
    platform = "android" if file_ext == ".apk" else "ios"

    # Create initial report record
    app_name = safe_basename.rsplit('.', 1)[0] if '.' in safe_basename else safe_basename
    report_data = {
        "app_name": app_name,
        "package_name": "analyzing...",
        "file_name": file.filename,
        "file_size": file_size,
        "md5_hash": md5_hash,
        "sha1_hash": sha1_hash,
        "sha256_hash": sha256_hash,
        "platform": platform
    }

    report_id = await ReportRepository.create(report_data)

    # Log upload
    logger.info(
        "File uploaded for analysis",
        extra_data={
            "report_id": report_id,
            "platform": platform,
            "file_size": file_size,
            "sha256": sha256_hash[:16]
        }
    )

    # Audit log if authenticated
    if current_user:
        await AuditLog.log(
            action="file_uploaded",
            user_id=current_user["id"],
            resource_type="report",
            resource_id=report_id,
            details=f"Uploaded {file.filename}",
            request=request
        )

    # Start background analysis based on platform
    if platform == "android":
        background_tasks.add_task(run_android_analysis, report_id, file_path)
    else:
        background_tasks.add_task(run_ios_analysis, report_id, file_path)

    return UploadResponse(
        report_id=report_id,
        message=f"File uploaded successfully. {platform.upper()} analysis started.",
        status=AnalysisStatus.PROCESSING,
        platform=Platform.IOS if platform == "ios" else Platform.ANDROID
    )


async def run_android_analysis(report_id: int, file_path: str):
    """Run complete APK analysis in background"""
    analysis_logger = AnalysisLogger(report_id)
    start_time = time.time()

    try:
        analysis_logger.start("android", os.path.basename(file_path))

        # Update status to processing
        await ReportRepository.update_status(report_id, "processing")

        # Run basic scanner
        analysis_logger.stage("basic_scan")
        scanner = APKScanner(file_path)
        basic_results = await scanner.analyze()

        # Update basic info
        basic_info = basic_results.get("basic_info", {})
        if basic_info.get("package_name"):
            from models.database import get_db_connection
            async with get_db_connection() as db:
                await db.execute("""
                    UPDATE reports SET
                        app_name = ?,
                        package_name = ?,
                        version_name = ?,
                        version_code = ?
                    WHERE id = ?
                """, (
                    basic_info.get("app_name"),
                    basic_info.get("package_name"),
                    basic_info.get("version_name"),
                    basic_info.get("version_code"),
                    report_id
                ))
                await db.commit()

        # Save manifest analysis
        analysis_logger.stage("manifest_analysis")
        if basic_results.get("manifest_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "manifest_analysis",
                basic_results["manifest_analysis"]
            )

        # Save certificate analysis
        analysis_logger.stage("certificate_analysis")
        if basic_results.get("certificate_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "certificate_analysis",
                basic_results["certificate_analysis"]
            )

        # Save binary analysis
        analysis_logger.stage("binary_analysis")
        if basic_results.get("binary_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "binary_analysis",
                basic_results["binary_analysis"]
            )

        # Run advanced code analysis
        analysis_logger.stage("code_analysis")
        advanced_scanner = AdvancedScanner(file_path)
        code_results = await advanced_scanner.analyze()

        # Combine all findings
        all_findings = basic_results.get("findings", [])
        code_analysis = code_results.get("code_analysis", {})
        all_findings.extend(code_analysis.get("findings", []))

        # Save findings to database (for pagination)
        analysis_logger.stage("saving_findings", {"count": len(all_findings)})
        if all_findings:
            await FindingRepository.bulk_insert(report_id, all_findings)

        # Get findings summary
        findings_summary = await FindingRepository.get_summary(report_id)

        # Save code analysis (without findings - they're in separate table)
        code_analysis_summary = {
            "total_files": code_analysis.get("total_files", 0),
            "total_lines": code_analysis.get("total_lines", 0),
            "java_files": code_analysis.get("java_files", 0),
            "kotlin_files": code_analysis.get("kotlin_files", 0),
            "smali_files": code_analysis.get("smali_files", 0),
            "findings_summary": findings_summary
        }
        await ReportRepository.update_analysis(
            report_id,
            "code_analysis",
            code_analysis_summary
        )

        # Update findings summary
        await ReportRepository.update_findings_summary(report_id, findings_summary)

        # Calculate risk score
        risk_score = calculate_risk_score(findings_summary)
        await ReportRepository.update_risk_score(report_id, risk_score)

        # Mark as completed
        await ReportRepository.update_status(
            report_id,
            "completed",
            datetime.utcnow()
        )

        duration = time.time() - start_time
        analysis_logger.complete(findings_summary.get("total", 0), risk_score, duration)

    except Exception as e:
        analysis_logger.error(str(e), "analysis")
        await ReportRepository.update_status(report_id, "failed")


async def run_ios_analysis(report_id: int, file_path: str):
    """Run complete IPA analysis in background"""
    analysis_logger = AnalysisLogger(report_id)
    start_time = time.time()

    try:
        analysis_logger.start("ios", os.path.basename(file_path))

        # Update status to processing
        await ReportRepository.update_status(report_id, "processing")

        # Run IPA scanner
        analysis_logger.stage("ipa_scan")
        scanner = IPAScanner(file_path)
        results = await scanner.analyze()

        # Update basic info
        basic_info = results.get("basic_info", {})
        if basic_info.get("package_name"):
            from models.database import get_db_connection
            async with get_db_connection() as db:
                await db.execute("""
                    UPDATE reports SET
                        app_name = ?,
                        package_name = ?,
                        version_name = ?,
                        version_code = ?
                    WHERE id = ?
                """, (
                    basic_info.get("app_name"),
                    basic_info.get("package_name"),
                    basic_info.get("version_name"),
                    basic_info.get("version_code", 0),
                    report_id
                ))
                await db.commit()

        # Save plist analysis (as manifest_analysis for compatibility)
        analysis_logger.stage("plist_analysis")
        if results.get("manifest_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "manifest_analysis",
                results["manifest_analysis"]
            )

        # Save entitlements analysis (as certificate_analysis for compatibility)
        analysis_logger.stage("entitlements_analysis")
        if results.get("certificate_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "certificate_analysis",
                results["certificate_analysis"]
            )

        # Save binary analysis
        analysis_logger.stage("binary_analysis")
        if results.get("binary_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "binary_analysis",
                results["binary_analysis"]
            )

        # Get findings
        all_findings = results.get("findings", [])

        # Save findings to database
        analysis_logger.stage("saving_findings", {"count": len(all_findings)})
        if all_findings:
            await FindingRepository.bulk_insert(report_id, all_findings)

        # Get findings summary
        findings_summary = await FindingRepository.get_summary(report_id)

        # Save code analysis summary
        code_analysis_summary = {
            "total_files": 0,
            "total_lines": 0,
            "swift_files": 0,
            "objc_files": 0,
            "findings_summary": findings_summary
        }
        await ReportRepository.update_analysis(
            report_id,
            "code_analysis",
            code_analysis_summary
        )

        # Update findings summary
        await ReportRepository.update_findings_summary(report_id, findings_summary)

        # Calculate risk score
        risk_score = calculate_risk_score(findings_summary)
        await ReportRepository.update_risk_score(report_id, risk_score)

        # Mark as completed
        await ReportRepository.update_status(
            report_id,
            "completed",
            datetime.utcnow()
        )

        duration = time.time() - start_time
        analysis_logger.complete(findings_summary.get("total", 0), risk_score, duration)

    except Exception as e:
        analysis_logger.error(str(e), "analysis")
        await ReportRepository.update_status(report_id, "failed")


def calculate_risk_score(summary: dict) -> int:
    """Calculate overall risk score (0-100)"""
    score = 0

    # Weight by severity
    score += summary.get("critical", 0) * 25
    score += summary.get("high", 0) * 15
    score += summary.get("medium", 0) * 8
    score += summary.get("low", 0) * 3
    score += summary.get("info", 0) * 1

    # Cap at 100
    return min(score, 100)


@app.get("/api/reports/{report_id}/status")
async def get_report_status(report_id: int):
    """Get analysis status for a report"""
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "report_id": report_id,
        "status": report["status"],
        "created_at": report["created_at"],
        "completed_at": report.get("completed_at")
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler with logging"""
    logger.error(
        f"Unhandled exception: {str(exc)}",
        extra_data={"path": request.url.path, "method": request.method}
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
