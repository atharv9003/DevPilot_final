"""
Agent-to-Agent (A2A) Protocol Definitions
JSON-RPC 2.0 schemas for interoperability between CrewAI and Google ADK agents.
"""
from pydantic import BaseModel, Field
from typing import Any, Optional, Dict, List, Union


class A2ARequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Union[str, int]
    method: str  # e.g., 'analyze_codebase', 'diagnose_root_cause', 'execute_sandbox_tests'
    params: Dict[str, Any] = Field(default_factory=dict)


class A2AError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


class A2AResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Union[str, int]
    result: Optional[Any] = None
    error: Optional[A2AError] = None


class A2AMessagePayload(BaseModel):
    sender: str
    receiver: str
    task_id: str
    action: str
    payload: Dict[str, Any]

