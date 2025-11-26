"""
AI Service Integration for Frida Script Generation
Supports both local AI (Ollama, LM Studio) and cloud AI (OpenAI, Anthropic)
"""

import os
import json
import httpx
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class AIProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"
    CUSTOM = "custom"


@dataclass
class AIConfig:
    """AI service configuration"""
    provider: AIProvider
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: str = "gpt-4"
    temperature: float = 0.7
    max_tokens: int = 4096
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AIConfig":
        return cls(
            provider=AIProvider(data.get("provider", "openai")),
            api_key=data.get("api_key"),
            base_url=data.get("base_url"),
            model=data.get("model", "gpt-4"),
            temperature=data.get("temperature", 0.7),
            max_tokens=data.get("max_tokens", 4096),
        )


# Default Frida script generation prompt
FRIDA_BYPASS_PROMPT = """You are an expert Android security researcher specializing in Frida instrumentation and bypass techniques.

Based on the following detected security mechanisms in an Android APK, generate a comprehensive Frida script to bypass them.

## Detected Security Mechanisms:

{findings_json}

## Summary:
- Root Detection Methods: {root_count}
- SSL Pinning Methods: {ssl_count}
- Native Protections: {native_count}
- Overall Bypass Difficulty: {difficulty}

## Requirements:
1. Generate a complete, working Frida script
2. Include bypasses for ALL detected mechanisms
3. Add detailed comments explaining each bypass
4. Handle edge cases and error conditions
5. Make the script modular so individual bypasses can be enabled/disabled
6. Include a configuration section at the top
7. Add logging for debugging purposes

## Output Format:
Provide ONLY the Frida JavaScript code, properly formatted and ready to use.
Start with a configuration object and organize bypasses by category (root detection, SSL pinning, native hooks).

Generate the Frida bypass script:
"""


class AIService:
    """Service for interacting with various AI providers"""
    
    def __init__(self, config: AIConfig):
        self.config = config
        self.client = httpx.AsyncClient(timeout=120.0)
        
    async def close(self):
        await self.client.aclose()
        
    async def generate_frida_script(
        self, 
        findings: Dict[str, Any],
        custom_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate Frida bypass script based on detected security mechanisms
        
        Args:
            findings: Security mechanism findings from RootSSLScanner
            custom_prompt: Optional custom prompt to use instead of default
            
        Returns:
            Dict containing the generated script and metadata
        """
        try:
            # Build the prompt
            prompt = self._build_prompt(findings, custom_prompt)
            
            # Call the appropriate AI provider
            if self.config.provider == AIProvider.OPENAI:
                response = await self._call_openai(prompt)
            elif self.config.provider == AIProvider.ANTHROPIC:
                response = await self._call_anthropic(prompt)
            elif self.config.provider == AIProvider.OLLAMA:
                response = await self._call_ollama(prompt)
            elif self.config.provider == AIProvider.LM_STUDIO:
                response = await self._call_lm_studio(prompt)
            elif self.config.provider == AIProvider.CUSTOM:
                response = await self._call_custom(prompt)
            else:
                raise ValueError(f"Unsupported AI provider: {self.config.provider}")
            
            return {
                "success": True,
                "script": response,
                "provider": self.config.provider.value,
                "model": self.config.model,
            }
            
        except Exception as e:
            logger.error(f"Error generating Frida script: {e}")
            return {
                "success": False,
                "error": str(e),
                "provider": self.config.provider.value,
            }
    
    def _build_prompt(
        self, 
        findings: Dict[str, Any], 
        custom_prompt: Optional[str] = None
    ) -> str:
        """Build the prompt for Frida script generation"""
        if custom_prompt:
            return custom_prompt
            
        summary = findings.get("summary", {})
        
        # Format findings for the prompt
        formatted_findings = {
            "root_detection": findings.get("root_detection", [])[:20],  # Limit to prevent token overflow
            "ssl_pinning": findings.get("ssl_pinning", [])[:20],
            "native_protection": findings.get("native_protection", [])[:10],
        }
        
        return FRIDA_BYPASS_PROMPT.format(
            findings_json=json.dumps(formatted_findings, indent=2),
            root_count=summary.get("root_detection_count", 0),
            ssl_count=summary.get("ssl_pinning_count", 0),
            native_count=summary.get("native_protection_count", 0),
            difficulty=summary.get("overall_bypass_difficulty", "unknown"),
        )
    
    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API"""
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        
        base_url = self.config.base_url or "https://api.openai.com/v1"
        
        data = {
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert Android security researcher and Frida developer."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        
        response = await self.client.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json=data
        )
        response.raise_for_status()
        
        result = response.json()
        return result["choices"][0]["message"]["content"]
    
    async def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude API"""
        headers = {
            "x-api-key": self.config.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        
        base_url = self.config.base_url or "https://api.anthropic.com/v1"
        
        data = {
            "model": self.config.model or "claude-3-sonnet-20240229",
            "max_tokens": self.config.max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "system": "You are an expert Android security researcher and Frida developer.",
        }
        
        response = await self.client.post(
            f"{base_url}/messages",
            headers=headers,
            json=data
        )
        response.raise_for_status()
        
        result = response.json()
        return result["content"][0]["text"]
    
    async def _call_ollama(self, prompt: str) -> str:
        """Call local Ollama API"""
        base_url = self.config.base_url or "http://localhost:11434"
        
        data = {
            "model": self.config.model or "llama2",
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            }
        }
        
        response = await self.client.post(
            f"{base_url}/api/generate",
            json=data
        )
        response.raise_for_status()
        
        result = response.json()
        return result["response"]
    
    async def _call_lm_studio(self, prompt: str) -> str:
        """Call LM Studio local API (OpenAI compatible)"""
        base_url = self.config.base_url or "http://localhost:1234/v1"
        
        data = {
            "model": self.config.model or "local-model",
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert Android security researcher and Frida developer."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        
        response = await self.client.post(
            f"{base_url}/chat/completions",
            json=data
        )
        response.raise_for_status()
        
        result = response.json()
        return result["choices"][0]["message"]["content"]
    
    async def _call_custom(self, prompt: str) -> str:
        """Call custom API endpoint (OpenAI compatible format)"""
        if not self.config.base_url:
            raise ValueError("Custom provider requires base_url")
            
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        
        data = {
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert Android security researcher and Frida developer."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        
        response = await self.client.post(
            f"{self.config.base_url}/chat/completions",
            headers=headers,
            json=data
        )
        response.raise_for_status()
        
        result = response.json()
        return result["choices"][0]["message"]["content"]
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test the AI connection"""
        try:
            test_prompt = "Say 'Connection successful!' in one short sentence."
            
            if self.config.provider == AIProvider.OPENAI:
                response = await self._call_openai(test_prompt)
            elif self.config.provider == AIProvider.ANTHROPIC:
                response = await self._call_anthropic(test_prompt)
            elif self.config.provider == AIProvider.OLLAMA:
                response = await self._call_ollama(test_prompt)
            elif self.config.provider == AIProvider.LM_STUDIO:
                response = await self._call_lm_studio(test_prompt)
            elif self.config.provider == AIProvider.CUSTOM:
                response = await self._call_custom(test_prompt)
            else:
                raise ValueError(f"Unsupported provider: {self.config.provider}")
                
            return {
                "success": True,
                "message": "Connection successful",
                "response": response[:100],
                "provider": self.config.provider.value,
                "model": self.config.model,
            }
        except Exception as e:
            return {
                "success": False,
                "message": str(e),
                "provider": self.config.provider.value,
            }


# AI Configuration storage (in-memory, can be persisted to DB)
_ai_config: Optional[AIConfig] = None


def get_ai_config() -> Optional[AIConfig]:
    """Get current AI configuration"""
    global _ai_config
    return _ai_config


def set_ai_config(config: AIConfig) -> None:
    """Set AI configuration"""
    global _ai_config
    _ai_config = config


async def generate_frida_bypass(findings: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate Frida bypass script using configured AI
    
    Args:
        findings: Security mechanism findings
        
    Returns:
        Generated script and metadata
    """
    config = get_ai_config()
    if not config:
        return {
            "success": False,
            "error": "AI not configured. Please configure AI settings first.",
        }
    
    service = AIService(config)
    try:
        return await service.generate_frida_script(findings)
    finally:
        await service.close()
