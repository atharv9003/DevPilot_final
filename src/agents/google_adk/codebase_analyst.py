"""
Google ADK Codebase Analyst Agent (Agent 1)
Inspects repository AST, extracts symbol hierarchies, builds call graphs,
indexes codebase chunks into the vector store, and maps project structure & LOC.
"""
import os
from typing import Dict, Any, Optional, List
from src.blackboard.store import BlackboardStore
from src.mcp_tools.ast_parser import ASTParserTool
from src.mcp_tools.vector_store import VectorCodebaseTool


from src.analysis.languages.manager import MultiLanguageManager


class CodebaseAnalystAgent:
    """Agent 1 – Code Understanding & Repository Analyst Agent."""

    def __init__(self, agent_id: str = "adk_codebase_analyst"):
        self.agent_id = agent_id
        self.lang_manager = MultiLanguageManager()

    def execute_analysis(self, blackboard: BlackboardStore) -> Dict[str, Any]:
        """Reads repo path from Blackboard, executes AST parse and vector indexing, and writes back."""
        state = blackboard.get_state()
        repo_path = state.repo_path

        # 1. Run AST Code Parser Tool
        ast_tool = ASTParserTool(repo_path=repo_path)
        ast_result = ast_tool.analyze_repository()

        # 2. Index into Vector Store Tool
        vector_tool = VectorCodebaseTool(collection_name=f"repo_{state.run_id}")
        chunks_indexed = vector_tool.index_files(repo_path, ast_result.files_analyzed)

        # 3. Post Findings to Blackboard
        blackboard.post_ast_analysis(
            agent_name=self.agent_id,
            ast_result=ast_result
        )

        return {
            "status": "success",
            "files_analyzed": len(ast_result.files_analyzed),
            "symbols_found": len(ast_result.symbols),
            "syntax_errors": len(ast_result.syntax_errors),
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
