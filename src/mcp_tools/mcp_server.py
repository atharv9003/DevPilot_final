"""
DevPilot MCP Server Implementation
Exposes the 4 core developer tools via Model Context Protocol (MCP) using FastMCP:
1. ast_code_parser
2. vector_codebase_search
3. tavily_web_search
4. docker_pytest_runner
"""
from typing import Optional, List, Dict, Any
from mcp.server.fastmcp import FastMCP
from src.mcp_tools.ast_parser import ASTParserTool
from src.mcp_tools.vector_store import VectorCodebaseTool
from src.mcp_tools.web_search import WebSearchTool
from src.mcp_tools.docker_sandbox import DockerSandboxTool

# Initialize standard FastMCP Server
mcp_server = FastMCP(
    name="DevPilot-MCP-Server"
)


@mcp_server.tool(
    name="ast_code_parser",
    description="Parses Python repository source code into AST symbol trees, call graphs, and extracts syntax errors."
)
def parse_ast(repo_path: str, target_files: Optional[List[str]] = None) -> Dict[str, Any]:
    """MCP Tool 1: AST Code Parser"""
    tool = ASTParserTool(repo_path=repo_path)
    result = tool.analyze_repository(target_files=target_files)
    return {
        "repo_path": result.repo_path,
        "files_analyzed": result.files_analyzed,
        "symbols": [s.model_dump() for s in result.symbols],
        "call_graph": result.call_graph,
        "syntax_errors": result.syntax_errors,
        "analysis_warnings": result.analysis_warnings,
    }


@mcp_server.tool(
    name="vector_codebase_search",
    description="Performs semantic vector search across indexed codebase chunks using dense neural embeddings."
)
def search_vector_codebase(
    query: str,
    repo_path: str,
    collection_name: Optional[str] = None,
    top_k: int = 3
) -> List[Dict[str, Any]]:
    """MCP Tool 2: Vector Codebase Search"""
    col = collection_name or "devpilot_codebase"
    tool = VectorCodebaseTool(collection_name=col)
    return tool.search_codebase(query=query, top_k=top_k)


@mcp_server.tool(
    name="tavily_web_search",
    description="Performs web search for technical documentation, exception fixes, and API usage."
)
def search_web_documentation(query: str, max_results: int = 3) -> List[Dict[str, str]]:
    """MCP Tool 3: Tavily Web Search"""
    tool = WebSearchTool()
    return tool.search(query=query, max_results=max_results)


@mcp_server.tool(
    name="docker_pytest_runner",
    description="Executes test suites inside a secure isolated Docker container with strict network isolation and resource limits."
)
def run_docker_pytest(
    repo_dir: str,
    test_file_path: Optional[str] = None,
    candidate_patch_diff: Optional[str] = None
) -> Dict[str, Any]:
    """MCP Tool 4: Docker pytest Runner"""
    tool = DockerSandboxTool()
    res = tool.run_tests(
        repo_dir=repo_dir,
        test_file_path=test_file_path,
        candidate_patch_diff=candidate_patch_diff
    )
    return res.model_dump()
