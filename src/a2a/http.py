"""HTTP transport shared by the dashboard and the standalone A2A worker."""
from hmac import compare_digest
from ipaddress import ip_address
from threading import Lock

from fastapi import APIRouter, FastAPI, Request

from config.settings import settings
from src.a2a.gateway import default_gateway
from src.a2a.protocol import A2AError, A2ARequest, A2AResponse
from src.agents.crewai.coordinator import CoordinatorAgent


router = APIRouter()
_registry_lock = Lock()


def _gateway():
    with _registry_lock:
        if not default_gateway.list_registered_methods():
            CoordinatorAgent(gateway=default_gateway)
    return default_gateway


def _trusted_client(request: Request) -> bool:
    token = settings.a2a_token
    if token:
        return compare_digest(request.headers.get("Authorization", "").encode(), f"Bearer {token}".encode())
    if "Origin" in request.headers:
        return False
    try:
        return bool(request.client and ip_address(request.client.host).is_loopback)
    except ValueError:
        return False


@router.post("/rpc", response_model=A2AResponse)
def a2a_rpc_endpoint(req: A2ARequest, request: Request):
    if req.method != "ping" and not _trusted_client(request):
        return A2AResponse(id=req.id, error=A2AError(code=-32001, message="A2A authentication required."))
    return _gateway().handle_request(req)


@router.get("/api/a2a/agents")
def get_a2a_agents():
    gateway = _gateway()
    return {
        "status": "success",
        "agents": gateway.list_registered_agents(),
        "methods": gateway.list_registered_methods(),
        "total_events": len(gateway.events),
    }


app = FastAPI(title="DevPilot A2A Worker")
app.include_router(router)
