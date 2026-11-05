"""
Agent-to-Agent (A2A) cross-framework communication package.
"""
from src.a2a.protocol import A2ARequest, A2AResponse, A2AError, A2AMessagePayload
from src.a2a.gateway import A2AGateway

__all__ = [
    "A2ARequest",
    "A2AResponse",
    "A2AError",
    "A2AMessagePayload",
    "A2AGateway"
]

