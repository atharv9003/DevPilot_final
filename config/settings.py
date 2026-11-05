"""
DevPilot System Configuration
Loads configuration from environment variables and provides defaults.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional
import os


class DevPilotSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Core LLM API Keys & Model
    gemini_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY"))
    gemini_base_url: Optional[str] = Field(default_factory=lambda: os.getenv("GEMINI_BASE_URL", "https://omnikey-ai-unified-key-manager.onrender.com"))
    gemini_model: str = Field(default="gemini-2.5-flash")
    openai_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))

    @property
    def clean_gemini_base_url(self) -> str:
        url = self.gemini_base_url or "https://omnikey-ai-unified-key-manager.onrender.com"
        return url.replace("/v1beta", "").rstrip("/")

    # Tool API Keys
    tavily_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("TAVILY_API_KEY"))

    # Blackboard Configuration
    blackboard_backend: str = Field(default="memory")  # 'memory' or 'redis'
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_db: int = Field(default=0)

    # Sandbox Execution
    docker_image: str = Field(default="python:3.11-slim")
    sandbox_timeout_seconds: int = Field(default=30)
    sandbox_max_memory: str = Field(default="512m")
    sandbox_max_cpus: float = Field(default=1.0)

    # A2A Gateway
    a2a_host: str = Field(default="127.0.0.1")
    a2a_port: int = Field(default=8484)

    # Telemetry
    langfuse_public_key: Optional[str] = Field(default_factory=lambda: os.getenv("LANGFUSE_PUBLIC_KEY"))
    langfuse_secret_key: Optional[str] = Field(default_factory=lambda: os.getenv("LANGFUSE_SECRET_KEY"))
    langfuse_host: str = Field(default="https://cloud.langfuse.com")
    enable_opentelemetry: bool = Field(default=True)


settings = DevPilotSettings()


def is_online(host: Optional[str] = None, port: int = 443, timeout: float = 1.5) -> bool:
    """Checks if external cloud network host is reachable with a strict fast timeout."""
    try:
        import socket
        import urllib.parse
        target_host = host
        if not target_host:
            if settings.gemini_base_url:
                parsed = urllib.parse.urlparse(settings.gemini_base_url)
                target_host = parsed.hostname or "omnikey-ai-unified-key-manager.onrender.com"
            else:
                target_host = "generativelanguage.googleapis.com"
        socket.create_connection((target_host, port), timeout=timeout).close()
        return True
    except Exception:
        return False
