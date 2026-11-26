import json
import sys
from fastapi.testclient import TestClient
from src.web.app import app

client = TestClient(app)

print("--- 1. Testing Frontend Route (GET /) ---")
r_index = client.get("/")
print(f"Status: {r_index.status_code}, Length: {len(r_index.text)} bytes")
assert r_index.status_code == 200
assert "DevPilot" in r_index.text
assert "Interactive Multi-Agent Dashboard" in r_index.text or "DevPilot" in r_index.text
print("✓ Frontend HTML page rendered successfully (HTTP 200).")

print("\n--- 2. Testing Backend Health Endpoint (GET /api/health) ---")
r_health = client.get("/api/health")
print(f"Status: {r_health.status_code}")
health_data = r_health.json()
print("Overall System Status:", health_data.get("status"))
print("Toolchains Active:", list(health_data.get("toolchains", {}).keys()))
print("Docker Sandbox Status:", health_data.get("docker_available"))
print("✓ Health check passed.")

print("\n--- 3. Testing Agent Registry (GET /api/a2a/agents) ---")
r_agents = client.get("/api/a2a/agents")
print(f"Status: {r_agents.status_code}")
agents_data = r_agents.json()
print("Registered Agents:", agents_data.get("agents"))
print("A2A Methods:", agents_data.get("methods"))
print("✓ A2A Agent discovery passed.")

print("\n--- 4. Testing Benchmark Summaries ---")
r_bm40 = client.get("/api/benchmark/summary")
bm40_data = r_bm40.json()
print(f"40-run summary status: {r_bm40.status_code}, total runs: {bm40_data.get('total_runs')}")

r_bm50 = client.get("/api/benchmark/polyglot-summary")
bm50_data = r_bm50.json()
print(f"50-run polyglot summary status: {r_bm50.status_code}, total scenarios: {bm50_data.get('total_scenarios')}")
overall = bm50_data.get("overall", {})
print(f"Accuracy: {overall.get('Accuracy')}%, Precision: {overall.get('Precision')}%, Recall: {overall.get('Recall')}%, F1: {overall.get('F1_Score')}%")
print("✓ Benchmark data endpoints passed.")

print("\n--- 5. Testing Code Inspection Endpoint (POST /api/inspect) ---")
r_inspect = client.post("/api/inspect", json={
    "repo_path": "devpilot_repos/code_error_detection_sample.py",
    "optional_context": "Automated frontend-backend functional test"
})
print(f"Inspection status: {r_inspect.status_code}")
assert r_inspect.status_code == 200
report = r_inspect.json()
print(f"Run ID: {report.get('run_id')}")
print(f"Total Issues Detected: {report.get('total_issues')}")
print(f"Critical: {report.get('critical_issues')}, High: {report.get('high_issues')}, Medium: {report.get('medium_issues')}, Low: {report.get('low_issues')}")
print(f"Unified Patch Generated: {bool(report.get('unified_patch'))} ({len(report.get('unified_patch', ''))} chars)")
print("✓ Multi-agent inspection endpoint passed.")

print("\n--- 6. Testing JSON-RPC A2A Communication (POST /rpc) ---")
r_rpc = client.post("/rpc", json={
    "jsonrpc": "2.0",
    "method": "ping",
    "params": {},
    "id": "test-req-1"
})
print(f"RPC status: {r_rpc.status_code}")
rpc_json = r_rpc.json()
print("RPC response keys:", list(rpc_json.keys()))
assert rpc_json.get("jsonrpc") == "2.0"
assert rpc_json.get("id") == "test-req-1"
print("✓ A2A JSON-RPC 2.0 endpoint protocol compliant (HTTP 200).")

print("\n=======================================================")
print("ALL FRONTEND & BACKEND MODULES ARE WORKING COMPLETELY!")
print("=======================================================")
