"""
A2A Gateway & Dispatcher
Routes JSON-RPC 2.0 messages between CrewAI Coordinator and Google ADK worker agents
both in-process and over HTTP via FastAPI, strictly enforcing JSON-serializable payloads.
"""
from typing import Dict, Callable, Any, List, Optional
import time
import json
import urllib.request
import urllib.error
from src.a2a.protocol import A2ARequest, A2AResponse, A2AError, A2ACommunicationEvent


class A2AGateway:
    def __init__(self):
        self._handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = {}
        self._agent_registry: Dict[str, Dict[str, Any]] = {}
        self.events: List[A2ACommunicationEvent] = []

    def register_agent(self, agent_name: str, framework: str, methods: List[str], endpoint: Optional[str] = None):
        """Registers agent capabilities and framework designation."""
        self._agent_registry[agent_name] = {
            "agent_name": agent_name,
            "framework": framework,
            "methods": methods,
            "endpoint": endpoint or "local://a2a"
        }

    def register_method(self, method_name: str, handler: Callable[[Dict[str, Any]], Any]):
        """Registers a worker agent procedure handler."""
        self._handlers[method_name] = handler

    def list_registered_methods(self) -> List[str]:
        return list(self._handlers.keys())

    def list_registered_agents(self) -> Dict[str, Dict[str, Any]]:
        return self._agent_registry

    def handle_request(self, request: A2ARequest, sender: str = "crewai_coordinator") -> A2AResponse:
        """Dispatches an A2A JSON-RPC request to the registered handler with strict serialization verification."""
        start_time = time.time()
        
        # Enforce strict serializability: no live object references allowed
        try:
            json.dumps(request.params)
        except (TypeError, ValueError) as e:
            err = A2AError(
                code=-32602,
                message=f"Invalid params: non-serializable object passed in A2A request: {e}"
            )
            return A2AResponse(id=request.id, error=err)

        handler = self._handlers.get(request.method)
        if not handler:
            err = A2AError(
                code=-32601,
                message=f"Method '{request.method}' not found in A2A gateway. Available: {list(self._handlers.keys())}"
            )
            return A2AResponse(id=request.id, error=err)

        try:
            raw_result = handler(request.params)
            # Ensure return result is also 100% JSON serializable
            json_compatible_result = json.loads(json.dumps(raw_result, default=str))
            
            duration_ms = round((time.time() - start_time) * 1000, 2)
            self.events.append(A2ACommunicationEvent(
                request_id=request.id,
                method=request.method,
                sender=sender,
                receiver=request.method,
                duration_ms=duration_ms,
                status="success"
            ))
            return A2AResponse(id=request.id, result=json_compatible_result)
        except Exception as e:
            duration_ms = round((time.time() - start_time) * 1000, 2)
            self.events.append(A2ACommunicationEvent(
                request_id=request.id,
                method=request.method,
                sender=sender,
                receiver=request.method,
                duration_ms=duration_ms,
                status="error",
                error_message=str(e)
            ))
            return A2AResponse(
                id=request.id,
                error=A2AError(
                    code=-32000,
                    message=f"Error executing method '{request.method}': {str(e)}"
                )
            )

    def dispatch(self, method: str, params: Dict[str, Any], req_id: str = "req_1", sender: str = "crewai_coordinator") -> Any:
        req = A2ARequest(id=req_id, method=method, params=params)
        res = self.handle_request(req, sender=sender)
        if res.error:
            raise RuntimeError(f"A2A RPC Error ({res.error.code}): {res.error.message}")
        return res.result

    def dispatch_http(self, url: str, method: str, params: Dict[str, Any], req_id: str = "req_1", token: Optional[str] = None) -> Any:
        """Sends an A2A JSON-RPC 2.0 request over HTTP."""
        req_payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params
        }
        data = json.dumps(req_payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "DevPilot-A2A-Client/1.0"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if "error" in body and body["error"]:
                raise RuntimeError(f"A2A HTTP Error ({body['error'].get('code')}): {body['error'].get('message')}")
            return body.get("result")


# Shared Global Gateway Instance
default_gateway = A2AGateway()
