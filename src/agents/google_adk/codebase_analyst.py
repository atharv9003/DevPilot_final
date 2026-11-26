"""
Google ADK Codebase Analyst Agent (Agent 1)
Inspects repository AST, extracts symbol hierarchies, builds call graphs,
indexes codebase chunks into the vector store, and maps project structure & LOC.
"""
import os
from typing import Dict, Any, Optional, List, Union
from src.blackboard.store import BlackboardStore
from src.blackboard.schema import ASTAnalysisResult, ASTSymbol
from src.mcp_tools.mcp_client import default_mcp_client
from src.mcp_tools.ast_parser import ASTParserTool
from src.mcp_tools.vector_store import VectorCodebaseTool
from src.analysis.languages.manager import MultiLanguageManager


class CodebaseAnalystAgent:
    """Agent 1 – Google ADK Code Understanding & Repository Analyst Agent."""

    def __init__(self, agent_id: str = "adk_codebase_analyst"):
        self.agent_id = agent_id
        self.lang_manager = MultiLanguageManager()
        self.mcp = default_mcp_client

    def execute_analysis(self, target: Union[BlackboardStore, str, Dict[str, Any]]) -> Dict[str, Any]:
        """Reads repo path from Blackboard, executes AST parse and vector indexing via MCP, and writes back."""
        repo_path: Optional[str] = None
        if isinstance(target, BlackboardStore):
            blackboard = target
            run_id = blackboard.run_id
        elif isinstance(target, dict):
            run_id = target.get("run_id", "default_run")
            repo_path = target.get("repo_path")
            blackboard = BlackboardStore(run_id=run_id)
        else:
            run_id = target if isinstance(target, str) else str(target)
            blackboard = BlackboardStore(run_id=run_id)

        if not repo_path:
            state = blackboard.get_state()
            repo_path = state.repo_path or "."

        # 1. Run AST Code Parser Tool via MCP
        mcp_ast_res = self.mcp.call_tool("ast_code_parser", {"repo_path": repo_path})
        ast_result = ASTAnalysisResult(
            repo_path=mcp_ast_res["repo_path"],
            files_analyzed=mcp_ast_res["files_analyzed"],
            symbols=[ASTSymbol(**s) for s in mcp_ast_res["symbols"]],
            call_graph=mcp_ast_res["call_graph"],
            syntax_errors=mcp_ast_res["syntax_errors"],
            analysis_warnings=mcp_ast_res.get("analysis_warnings", []),
        )

        # 2. RAG/Vector embeddings disabled per requirements to maximize inspection speed
        chunks_indexed = 0

        # 3. Post Findings to Blackboard
        blackboard.post_ast_analysis(
            agent_name=self.agent_id,
            ast_result=ast_result
        )

        return {
            "status": "success",
            "run_id": run_id,
            "files_analyzed": len(ast_result.files_analyzed),
            "symbols_found": len(ast_result.symbols),
            "syntax_errors": len(ast_result.syntax_errors),
            "analysis_warnings": ast_result.analysis_warnings,
            "chunks_indexed": chunks_indexed
        }

    def inspect_codebase(self, repo_path: str) -> Dict[str, Any]:
        """
        Gathers multi-language structural metrics for full code inspection:
        total files, lines of code, languages detected, scannable files, and manifests.
        """
        proj = self.lang_manager.inspect_project_structure(repo_path)
        return {
            "total_files": proj["total_files"],
            "total_loc": proj["total_loc"],
            "languages_detected": proj["languages_detected"],
            "python_files": proj["all_scannable_files"],  # backward-compatible key name
            "all_scannable_files": proj["all_scannable_files"],
            "files_by_language": proj["files_by_language"],
            "manifests_found": proj["manifests_found"],
            "toolchain_status": proj["toolchain_status"]
        }
