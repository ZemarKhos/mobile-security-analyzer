"""
AI Integration API Routes
Endpoints for AI configuration and Frida script generation
"""

import os
import json
import logging
import zipfile
import tempfile
import shutil
from typing import Optional
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field

from ai_service import (
    AIConfig, 
    AIProvider, 
    AIService,
    get_ai_config, 
    set_ai_config,
    generate_frida_bypass
)
from root_ssl_scanner import scan_for_security_mechanisms

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["AI Integration"])

# Store for temporary extraction paths (keyed by report_id)
_temp_extraction_dirs: dict = {}


async def get_apk_extracted_dir(report_id: str, report: dict) -> str:
    """
    Get or create decompiled APK directory for security scanning.
    Uses APKTool to properly decompile APK to smali format.
    """
    import subprocess
    
    upload_dir = os.getenv("UPLOAD_DIR", "/app/uploads")
    
    # Check if we already have an extracted dir for this report
    if report_id in _temp_extraction_dirs:
        temp_dir = _temp_extraction_dirs[report_id]
        if os.path.isdir(temp_dir):
            return temp_dir
    
    # Find APK file - look for file matching the report
    file_name = report.get("file_name")
    if not file_name:
        raise HTTPException(status_code=404, detail="APK filename not found in report")
    
    # APK might be stored with hash prefix
    apk_path = None
    for f in os.listdir(upload_dir):
        if f.endswith('.apk') and (f == file_name or f.endswith(f"_{file_name}") or file_name in f):
            apk_path = os.path.join(upload_dir, f)
            break
    
    if not apk_path or not os.path.exists(apk_path):
        raise HTTPException(status_code=404, detail="APK file not found. It may have been deleted.")
    
    # Decompile APK using apktool to get smali files
    temp_dir = tempfile.mkdtemp(prefix=f"mobai_security_{report_id}_")
    
    try:
        # Try APKTool first for proper decompilation (smali + resources)
        result = subprocess.run(
            ["apktool", "d", "-f", apk_path, "-o", temp_dir],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            logger.info(f"Decompiled APK with apktool: {apk_path} -> {temp_dir}")
        else:
            logger.warning(f"APKTool failed: {result.stderr}, falling back to zip extraction")
            # Fallback to simple zip extraction if apktool fails
            shutil.rmtree(temp_dir)
            temp_dir = tempfile.mkdtemp(prefix=f"mobai_security_{report_id}_")
            with zipfile.ZipFile(apk_path, 'r') as z:
                z.extractall(temp_dir)
            logger.info(f"Extracted APK as zip: {apk_path} -> {temp_dir}")
        
        # Store for reuse and cleanup
        _temp_extraction_dirs[report_id] = temp_dir
        
        return temp_dir
        
    except subprocess.TimeoutExpired:
        logger.error("APKTool timed out, falling back to zip extraction")
        shutil.rmtree(temp_dir)
        temp_dir = tempfile.mkdtemp(prefix=f"mobai_security_{report_id}_")
        with zipfile.ZipFile(apk_path, 'r') as z:
            z.extractall(temp_dir)
        _temp_extraction_dirs[report_id] = temp_dir
        return temp_dir
        
    except Exception as e:
        # Cleanup on error
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        logger.error(f"Error decompiling APK: {e}")
        raise HTTPException(status_code=500, detail=f"Error decompiling APK: {str(e)}")


def cleanup_extraction(report_id: str):
    """Cleanup temporary extraction directory for a report"""
    if report_id in _temp_extraction_dirs:
        temp_dir = _temp_extraction_dirs.pop(report_id)
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up extraction dir for report {report_id}")
            except Exception as e:
                logger.error(f"Error cleaning up extraction dir: {e}")

# Config file path
AI_CONFIG_FILE = os.path.join(os.getenv("DATA_DIR", "/app/data"), "ai_config.json")


# Pydantic models for API
class AIConfigRequest(BaseModel):
    """Request model for AI configuration"""
    provider: str = Field(..., description="AI provider: openai, anthropic, ollama, lm_studio, custom")
    api_key: Optional[str] = Field(None, description="API key (for cloud providers)")
    base_url: Optional[str] = Field(None, description="Custom base URL")
    model: str = Field("gpt-4", description="Model name")
    temperature: float = Field(0.7, ge=0, le=2, description="Temperature for generation")
    max_tokens: int = Field(4096, ge=100, le=32000, description="Max tokens for response")


class AIConfigResponse(BaseModel):
    """Response model for AI configuration status"""
    configured: bool
    provider: Optional[str] = None
    model: Optional[str] = None
    base_url: Optional[str] = None
    # Never return API key


class GenerateFridaRequest(BaseModel):
    """Request model for Frida script generation"""
    report_id: str = Field(..., description="Report ID to generate bypass for")
    custom_prompt: Optional[str] = Field(None, description="Optional custom prompt")


class GenerateFridaResponse(BaseModel):
    """Response model for generated Frida script"""
    success: bool
    script: Optional[str] = None
    error: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None


# Load config on startup
def load_ai_config():
    """Load AI configuration from file"""
    try:
        if os.path.exists(AI_CONFIG_FILE):
            with open(AI_CONFIG_FILE, 'r') as f:
                data = json.load(f)
                config = AIConfig.from_dict(data)
                set_ai_config(config)
                logger.info(f"Loaded AI config: provider={config.provider.value}, model={config.model}")
    except Exception as e:
        logger.error(f"Error loading AI config: {e}")


def save_ai_config(config: AIConfig):
    """Save AI configuration to file"""
    try:
        os.makedirs(os.path.dirname(AI_CONFIG_FILE), exist_ok=True)
        data = {
            "provider": config.provider.value,
            "api_key": config.api_key,
            "base_url": config.base_url,
            "model": config.model,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        }
        with open(AI_CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info("AI config saved")
    except Exception as e:
        logger.error(f"Error saving AI config: {e}")


# Initialize config on module load
load_ai_config()


@router.get("/config", response_model=AIConfigResponse)
async def get_config():
    """Get current AI configuration (without sensitive data)"""
    config = get_ai_config()
    if not config:
        return AIConfigResponse(configured=False)
    
    return AIConfigResponse(
        configured=True,
        provider=config.provider.value,
        model=config.model,
        base_url=config.base_url if config.provider in [AIProvider.OLLAMA, AIProvider.LM_STUDIO, AIProvider.CUSTOM] else None,
    )


@router.post("/config")
async def update_config(request: AIConfigRequest):
    """Update AI configuration"""
    try:
        # Validate provider
        try:
            provider = AIProvider(request.provider)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid provider. Must be one of: {[p.value for p in AIProvider]}"
            )
        
        # Validate required fields based on provider
        if provider in [AIProvider.OPENAI, AIProvider.ANTHROPIC]:
            if not request.api_key:
                raise HTTPException(
                    status_code=400,
                    detail=f"API key required for {provider.value}"
                )
        
        if provider in [AIProvider.OLLAMA, AIProvider.LM_STUDIO] and not request.base_url:
            # Set defaults - use host.docker.internal for Docker compatibility
            if provider == AIProvider.OLLAMA:
                request.base_url = "http://host.docker.internal:11434"
            else:
                request.base_url = "http://host.docker.internal:1234/v1"
        
        if provider == AIProvider.CUSTOM and not request.base_url:
            raise HTTPException(
                status_code=400,
                detail="base_url required for custom provider"
            )
        
        # Create config
        config = AIConfig(
            provider=provider,
            api_key=request.api_key,
            base_url=request.base_url,
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
        
        # Save and set
        set_ai_config(config)
        save_ai_config(config)
        
        return {
            "success": True,
            "message": "AI configuration updated",
            "provider": provider.value,
            "model": request.model,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating AI config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/config")
async def delete_config():
    """Remove AI configuration"""
    try:
        set_ai_config(None)
        if os.path.exists(AI_CONFIG_FILE):
            os.remove(AI_CONFIG_FILE)
        return {"success": True, "message": "AI configuration removed"}
    except Exception as e:
        logger.error(f"Error deleting AI config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test")
async def test_connection():
    """Test AI connection"""
    config = get_ai_config()
    if not config:
        raise HTTPException(
            status_code=400,
            detail="AI not configured. Please configure AI settings first."
        )
    
    service = AIService(config)
    try:
        result = await service.test_connection()
        if not result["success"]:
            raise HTTPException(status_code=400, detail=result["message"])
        return result
    finally:
        await service.close()


@router.get("/providers")
async def get_providers():
    """Get available AI providers with their configuration requirements"""
    return {
        "providers": [
            {
                "id": "openai",
                "name": "OpenAI",
                "description": "GPT-4, GPT-3.5-turbo via OpenAI API",
                "requires_api_key": True,
                "requires_base_url": False,
                "default_model": "gpt-4",
                "models": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"],
            },
            {
                "id": "anthropic",
                "name": "Anthropic Claude",
                "description": "Claude 3 models via Anthropic API",
                "requires_api_key": True,
                "requires_base_url": False,
                "default_model": "claude-3-sonnet-20240229",
                "models": ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"],
            },
            {
                "id": "ollama",
                "name": "Ollama (Local)",
                "description": "Run AI locally with Ollama. Use host.docker.internal for Docker.",
                "requires_api_key": False,
                "requires_base_url": True,
                "default_base_url": "http://host.docker.internal:11434",
                "default_model": "llama2",
                "models": ["llama2", "codellama", "mistral", "mixtral", "deepseek-coder"],
            },
            {
                "id": "lm_studio",
                "name": "LM Studio (Local)",
                "description": "Run AI locally with LM Studio. Use host.docker.internal for Docker.",
                "requires_api_key": False,
                "requires_base_url": True,
                "default_base_url": "http://host.docker.internal:1234/v1",
                "default_model": "local-model",
                "models": [],
            },
            {
                "id": "custom",
                "name": "Custom API",
                "description": "Any OpenAI-compatible API endpoint",
                "requires_api_key": False,
                "requires_base_url": True,
                "default_model": "default",
                "models": [],
            },
        ]
    }


@router.post("/generate-frida/{report_id}", response_model=GenerateFridaResponse)
async def generate_frida_script(report_id: str, custom_prompt: Optional[str] = Body(None)):
    """Generate Frida bypass script for a report"""
    from models.database import ReportRepository
    
    config = get_ai_config()
    if not config:
        return GenerateFridaResponse(
            success=False,
            error="AI not configured. Please configure AI settings first."
        )
    
    # Get report
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Get or extract APK for scanning
    try:
        extracted_dir = await get_apk_extracted_dir(report_id, report)
    except HTTPException as e:
        return GenerateFridaResponse(
            success=False,
            error=e.detail
        )
    
    # Run security mechanism scan
    try:
        findings = scan_for_security_mechanisms(extracted_dir)
    except Exception as e:
        logger.error(f"Error scanning for security mechanisms: {e}")
        cleanup_extraction(report_id)
        return GenerateFridaResponse(
            success=False,
            error=f"Error scanning APK: {str(e)}"
        )
    
    if findings["summary"]["total_findings"] == 0:
        cleanup_extraction(report_id)
        return GenerateFridaResponse(
            success=False,
            error="No root detection or SSL pinning mechanisms found in this APK."
        )
    
    # Generate Frida script
    service = AIService(config)
    try:
        result = await service.generate_frida_script(findings, custom_prompt)
        
        if result["success"]:
            return GenerateFridaResponse(
                success=True,
                script=result["script"],
                provider=result.get("provider"),
                model=result.get("model"),
            )
        else:
            return GenerateFridaResponse(
                success=False,
                error=result.get("error", "Unknown error"),
                provider=result.get("provider"),
            )
    finally:
        await service.close()
        # Cleanup extracted files after AI generation
        cleanup_extraction(report_id)


@router.get("/security-scan/{report_id}")
async def get_security_mechanisms(report_id: str):
    """Get root detection and SSL pinning scan results for a report"""
    from models.database import ReportRepository
    
    # Get report
    report = await ReportRepository.get_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Get or extract APK for scanning
    try:
        extracted_dir = await get_apk_extracted_dir(report_id, report)
    except HTTPException as e:
        raise e
    
    try:
        findings = scan_for_security_mechanisms(extracted_dir)
        return findings
    except Exception as e:
        logger.error(f"Error scanning for security mechanisms: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Cleanup after scan
        cleanup_extraction(report_id)
