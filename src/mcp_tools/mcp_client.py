"""
DevPilot MCP Client Interface
Connects agents to the registered MCP tools with schema validation, error handling, and telemetry.
"""
from typing import Dict, Any, Optional, List
import time
from src.mcp_tools.mcp_server import mcp_server


class DevPilotMCPClient:
    """Client for invoking Model Context Protocol (MCP) tools."""

    def __init__(self, server=None):
        self.server = server or mcp_server
        self._tool_cache: Dict[str, Any] = {}
        self._load_tools()

    def _load_tools(self):
        """Loads registered tools from FastMCP server."""
        for tool in self.server._tool_manager.list_tools():
            self._tool_cache[tool.name] = tool

    def list_available_tools(self) -> List[Dict[str, Any]]:
        """Returns schemas of all registered MCP tools."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters
            }
            for t in self.server._tool_manager.list_tools()
        ]

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Invokes an MCP tool with runtime argument boundary security validation and error trapping."""
        if tool_name not in self._tool_cache:
            self._load_tools()

        if tool_name not in self._tool_cache:
            raise KeyError(f"MCP Tool '{tool_name}' not found. Available tools: {list(self._tool_cache.keys())}")

        # Runtime tool execution boundary validation
        from src.guardrails.input_filter import InputSecurityGuardrail
        guard = InputSecurityGuardrail()
        val_res = guard.validate_tool_arguments(tool_name, arguments)
        if not val_res.is_allowed:
            raise PermissionError(f"Tool execution blocked by security guardrails: {'; '.join(val_res.violations)}")

        tool = self._tool_cache[tool_name]
        try:
            # Execute tool through FastMCP tool handler
            return tool.fn(**val_res.sanitized_arguments)
        except Exception as e:
            raise RuntimeError(f"MCP Tool '{tool_name}' execution error: {e}") from e


# Global shared MCP client instance
default_mcp_client = DevPilotMCPClient()
