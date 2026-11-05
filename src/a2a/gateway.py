"""
A2A Gateway & Dispatcher
Routes JSON-RPC 2.0 messages between CrewAI Coordinator and Google ADK worker agents
both in-process and over HTTP via FastAPI.
"""
from typing import Dict, Callable, Any
from src.a2a.protocol import A2ARequest, A2AResponse, A2AError


class A2AGateway:
    def __init__(self):
        self._handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = {}

    def register_method(self, method_name: str, handler: Callable[[Dict[str, Any]], Any]):
        """Registers a worker agent procedure handler."""
        self._handlers[method_name] = handler

    def handle_request(self, request: A2ARequest) -> A2AResponse:
        """Dispatches an A2A JSON-RPC request to the registered handler."""
        handler = self._handlers.get(request.method)
        if not handler:
            return A2AResponse(
                id=request.id,
                error=A2AError(
                    code=-32601,
                    message=f"Method '{request.method}' not found in A2A gateway"
                )
            )

        try:
            result = handler(request.params)
            return A2AResponse(id=request.id, result=result)
        except Exception as e:
            return A2AResponse(
                id=request.id,
                error=A2AError(
                    code=-32000,
                    message=f"Error executing method '{request.method}': {str(e)}"
                )
            )

    def dispatch(self, method: str, params: Dict[str, Any], req_id: str = "req_1") -> Any:
        req = A2ARequest(id=req_id, method=method, params=params)
        res = self.handle_request(req)
        if res.error:
            raise RuntimeError(f"A2A RPC Error ({res.error.code}): {res.error.message}")
        return res.result


# Shared Global Gateway Instance
default_gateway = A2AGateway()

# FastAPI Microservice App for HTTP JSON-RPC transport
try:
    from fastapi import FastAPI, Body
    app = FastAPI(title="DevPilot A2A Protocol Gateway", version="1.0.0")

    @app.post("/rpc", response_model=A2AResponse)
    async def rpc_endpoint(request: A2ARequest = Body(...)):
        return default_gateway.handle_request(request)

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": "devpilot_a2a_gateway"}
except ImportError:
    app = None
