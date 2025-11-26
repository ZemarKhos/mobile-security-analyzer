"""
Mobile Analyzer - FastAPI Backend
Main application entry point
"""

import os
import hashlib
import shutil
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from models.database import init_database, ReportRepository, FindingRepository
from models.schemas import UploadResponse, HealthResponse, AnalysisStatus, Platform
from scanner import APKScanner
from advanced_scanner import AdvancedScanner
from ipa_scanner import IPAScanner
from reports_api import router as reports_router
from ai_api import router as ai_router
from rules_api import router as rules_router

# Configuration
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
DATA_DIR = os.getenv("DATA_DIR", "/app/data")
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB

# Supported file types
SUPPORTED_EXTENSIONS = {'.apk', '.ipa'}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    print("Starting Mobile Analyzer...")
    
    # Ensure directories exist
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # Initialize database
    await init_database()
    
    print("Mobile Analyzer started successfully!")
    yield
    
    # Shutdown
    print("Shutting down Mobile Analyzer...")


# Create FastAPI app
app = FastAPI(
    title="Mobile Analyzer",
    description="Android APK Security Analysis Tool - MobSF Alternative",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(reports_router)
app.include_router(ai_router)
app.include_router(rules_router)


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow()
    )


@app.post("/api/upload", response_model=UploadResponse)
async def upload_app(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="APK or IPA file to analyze")
):
    """
    Upload an APK or IPA file for analysis.
    
    The file is saved and analysis is started in the background.
    Returns immediately with a report ID to track progress.
    
    Supported formats:
    - .apk (Android)
    - .ipa (iOS)
    """
    # Validate file extension
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
    
    # Generate unique filename with hash
    content = await file.read()
    file_hash = hashlib.md5(content).hexdigest()[:8]
    safe_filename = f"{file_hash}_{file.filename}"
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
    app_name = file.filename.replace(".apk", "").replace(".ipa", "")
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
    try:
        # Update status to processing
        await ReportRepository.update_status(report_id, "processing")
        
        # Run basic scanner
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
        if basic_results.get("manifest_analysis"):
            await ReportRepository.update_analysis(
                report_id, 
                "manifest_analysis",
                basic_results["manifest_analysis"]
            )
        
        # Save certificate analysis
        if basic_results.get("certificate_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "certificate_analysis", 
                basic_results["certificate_analysis"]
            )
        
        # Save binary analysis
        if basic_results.get("binary_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "binary_analysis",
                basic_results["binary_analysis"]
            )
        
        # Run advanced code analysis
        advanced_scanner = AdvancedScanner(file_path)
        code_results = await advanced_scanner.analyze()
        
        # Combine all findings
        all_findings = basic_results.get("findings", [])
        code_analysis = code_results.get("code_analysis", {})
        all_findings.extend(code_analysis.get("findings", []))
        
        # Save findings to database (for pagination)
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
        
        print(f"Android analysis completed for report {report_id}")
        
    except Exception as e:
        print(f"Android analysis failed for report {report_id}: {e}")
        await ReportRepository.update_status(report_id, "failed")
    
    finally:
        pass


async def run_ios_analysis(report_id: int, file_path: str):
    """Run complete IPA analysis in background"""
    try:
        # Update status to processing
        await ReportRepository.update_status(report_id, "processing")
        
        # Run IPA scanner
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
        if results.get("manifest_analysis"):
            await ReportRepository.update_analysis(
                report_id, 
                "manifest_analysis",
                results["manifest_analysis"]
            )
        
        # Save entitlements analysis (as certificate_analysis for compatibility)
        if results.get("certificate_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "certificate_analysis", 
                results["certificate_analysis"]
            )
        
        # Save binary analysis
        if results.get("binary_analysis"):
            await ReportRepository.update_analysis(
                report_id,
                "binary_analysis",
                results["binary_analysis"]
            )
        
        # Get findings
        all_findings = results.get("findings", [])
        
        # Save findings to database
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
        
        print(f"iOS analysis completed for report {report_id}")
        
    except Exception as e:
        print(f"iOS analysis failed for report {report_id}: {e}")
        import traceback
        traceback.print_exc()
        await ReportRepository.update_status(report_id, "failed")
    
    finally:
        pass


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
async def global_exception_handler(request, exc):
    """Global exception handler"""
    print(f"Unhandled exception: {exc}")
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
