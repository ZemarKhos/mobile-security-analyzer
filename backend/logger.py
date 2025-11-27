"""
Structured Logging System for Mobile Analyzer
Provides consistent logging across all modules with JSON output support
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Optional, Any, Dict
from functools import wraps
import traceback
import time

# Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv("LOG_FORMAT", "json")  # "json" or "text"
LOG_FILE = os.getenv("LOG_FILE", None)  # Optional file path


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info)
            }

        return json.dumps(log_data, default=str)


class TextFormatter(logging.Formatter):
    """Colored text formatter for development"""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        # Base message
        msg = f"{color}[{timestamp}] {record.levelname:8}{self.RESET} "
        msg += f"{record.name}:{record.funcName}:{record.lineno} - {record.getMessage()}"

        # Add extra data if present
        if hasattr(record, "extra_data") and record.extra_data:
            extras = " | ".join(f"{k}={v}" for k, v in record.extra_data.items())
            msg += f" | {extras}"

        # Add exception if present
        if record.exc_info:
            msg += f"\n{self.formatException(record.exc_info)}"

        return msg


class ContextLogger(logging.Logger):
    """Extended logger with context support"""

    def __init__(self, name: str, level: int = logging.NOTSET):
        super().__init__(name, level)
        self._context: Dict[str, Any] = {}

    def set_context(self, **kwargs):
        """Set persistent context for all log messages"""
        self._context.update(kwargs)

    def clear_context(self):
        """Clear all context"""
        self._context = {}

    def _log_with_extra(self, level: int, msg: str, args, exc_info=None, extra_data: Dict = None, **kwargs):
        """Internal log method with extra data support"""
        if extra_data is None:
            extra_data = {}

        # Merge context with extra data
        merged_extra = {**self._context, **extra_data}

        # Create custom record
        extra = kwargs.get("extra", {})
        extra["extra_data"] = merged_extra
        kwargs["extra"] = extra

        super()._log(level, msg, args, exc_info=exc_info, **kwargs)

    def debug(self, msg: str, *args, extra_data: Dict = None, **kwargs):
        self._log_with_extra(logging.DEBUG, msg, args, extra_data=extra_data, **kwargs)

    def info(self, msg: str, *args, extra_data: Dict = None, **kwargs):
        self._log_with_extra(logging.INFO, msg, args, extra_data=extra_data, **kwargs)

    def warning(self, msg: str, *args, extra_data: Dict = None, **kwargs):
        self._log_with_extra(logging.WARNING, msg, args, extra_data=extra_data, **kwargs)

    def error(self, msg: str, *args, extra_data: Dict = None, exc_info=True, **kwargs):
        self._log_with_extra(logging.ERROR, msg, args, exc_info=exc_info, extra_data=extra_data, **kwargs)

    def critical(self, msg: str, *args, extra_data: Dict = None, exc_info=True, **kwargs):
        self._log_with_extra(logging.CRITICAL, msg, args, exc_info=exc_info, extra_data=extra_data, **kwargs)


def setup_logging():
    """Setup logging configuration"""
    # Set custom logger class
    logging.setLoggerClass(ContextLogger)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, LOG_LEVEL))

    # Clear existing handlers
    root_logger.handlers = []

    # Create formatter based on config
    if LOG_FORMAT == "json":
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if LOG_FILE:
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(JSONFormatter())  # Always JSON for files
        root_logger.addHandler(file_handler)

    # Suppress noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> ContextLogger:
    """Get a logger instance"""
    return logging.getLogger(name)


# Decorators for common logging patterns

def log_execution(logger: Optional[ContextLogger] = None):
    """Decorator to log function execution time"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            log = logger or get_logger(func.__module__)
            start_time = time.time()
            func_name = func.__name__

            log.debug(f"Starting {func_name}", extra_data={"function": func_name})

            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                log.debug(
                    f"Completed {func_name}",
                    extra_data={"function": func_name, "duration_ms": round(duration * 1000, 2)}
                )
                return result
            except Exception as e:
                duration = time.time() - start_time
                log.error(
                    f"Failed {func_name}: {str(e)}",
                    extra_data={"function": func_name, "duration_ms": round(duration * 1000, 2)}
                )
                raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            log = logger or get_logger(func.__module__)
            start_time = time.time()
            func_name = func.__name__

            log.debug(f"Starting {func_name}", extra_data={"function": func_name})

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                log.debug(
                    f"Completed {func_name}",
                    extra_data={"function": func_name, "duration_ms": round(duration * 1000, 2)}
                )
                return result
            except Exception as e:
                duration = time.time() - start_time
                log.error(
                    f"Failed {func_name}: {str(e)}",
                    extra_data={"function": func_name, "duration_ms": round(duration * 1000, 2)}
                )
                raise

        if asyncio_iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


def asyncio_iscoroutinefunction(func):
    """Check if function is async"""
    import asyncio
    return asyncio.iscoroutinefunction(func)


# Request logging middleware
class RequestLoggingMiddleware:
    """Middleware to log all HTTP requests"""

    def __init__(self, app):
        self.app = app
        self.logger = get_logger("http")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.time()
        path = scope.get("path", "")
        method = scope.get("method", "")

        # Capture response status
        status_code = 500

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.time() - start_time
            duration_ms = round(duration * 1000, 2)

            # Get client IP
            client = scope.get("client")
            client_ip = client[0] if client else "unknown"

            log_data = {
                "method": method,
                "path": path,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "client_ip": client_ip
            }

            if status_code >= 500:
                self.logger.error("Request failed", extra_data=log_data, exc_info=False)
            elif status_code >= 400:
                self.logger.warning("Request error", extra_data=log_data)
            else:
                self.logger.info("Request completed", extra_data=log_data)


# Analysis-specific logging
class AnalysisLogger:
    """Specialized logger for analysis operations"""

    def __init__(self, report_id: int):
        self.logger = get_logger("analysis")
        self.report_id = report_id
        self.logger.set_context(report_id=report_id)

    def start(self, platform: str, file_name: str):
        self.logger.info(
            f"Starting {platform} analysis",
            extra_data={"platform": platform, "file_name": file_name, "stage": "start"}
        )

    def stage(self, stage_name: str, details: Dict = None):
        self.logger.info(
            f"Analysis stage: {stage_name}",
            extra_data={"stage": stage_name, **(details or {})}
        )

    def finding(self, severity: str, finding_type: str, title: str):
        self.logger.debug(
            f"Finding detected: {title}",
            extra_data={"severity": severity, "finding_type": finding_type}
        )

    def complete(self, findings_count: int, risk_score: int, duration_seconds: float):
        self.logger.info(
            "Analysis completed",
            extra_data={
                "stage": "complete",
                "findings_count": findings_count,
                "risk_score": risk_score,
                "duration_seconds": round(duration_seconds, 2)
            }
        )

    def error(self, error_msg: str, stage: str = None):
        self.logger.error(
            f"Analysis failed: {error_msg}",
            extra_data={"stage": stage or "unknown"},
            exc_info=True
        )


# Initialize logging when module is imported
setup_logging()
