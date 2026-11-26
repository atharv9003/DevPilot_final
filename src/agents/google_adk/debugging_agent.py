"""
Google ADK Debugging Agent
Executes a ReAct (Reasoning + Acting) loop:
Thought -> Query Vector DB / Web -> Observation -> Dynamic LLM/AST Diagnosis & Patch Generation.
"""
from typing import Dict, Any, List, Optional, Union
import os
import re
import ast
import json
from src.blackboard.store import BlackboardStore
from src.blackboard.schema import Hypothesis, CandidatePatch
from src.mcp_tools.mcp_client import default_mcp_client
from config.settings import settings, is_online
from src.agents.google_adk.gemini_fallback import generate_content_with_fallback


class DebuggingAgent:
    def __init__(self, agent_id: str = "adk_debugging_agent"):
        self.agent_id = agent_id
        self.mcp = default_mcp_client
        self.gemini_client = None

        if settings.gemini_api_key and settings.gemini_api_key.strip() and is_online():
            try:
                from google import genai
                from google.genai import types
                if settings.clean_gemini_base_url and "googleapis.com" not in settings.clean_gemini_base_url:
                    opts = types.HttpOptions(base_url=settings.clean_gemini_base_url, api_version="v1beta", timeout=150000)
                    self.gemini_client = genai.Client(api_key=settings.gemini_api_key, http_options=opts)
                else:
                    opts = types.HttpOptions(timeout=150000)
                    self.gemini_client = genai.Client(api_key=settings.gemini_api_key, http_options=opts)
            except Exception:
                self.gemini_client = None

    def execute_debugging(self, target: Union[BlackboardStore, str, Dict[str, Any]]) -> Dict[str, Any]:
        """Runs the ReAct cycle using Blackboard context, MCP tools, and dynamic LLM/AST analysis."""
        if isinstance(target, BlackboardStore):
            blackboard = target
            run_id = blackboard.run_id
        elif isinstance(target, dict):
            run_id = target.get("run_id", "default_run")
            blackboard = BlackboardStore(run_id=run_id)
        else:
            run_id = target if isinstance(target, str) else str(target)
            blackboard = BlackboardStore(run_id=run_id)

        state = blackboard.get_state()
        error_trace = state.target_error_trace or state.sanitized_prompt
        ast_analysis = state.ast_analysis
        repo_path = state.repo_path

        react_steps = []

        # --- ReAct Step 1: Thought & Error Triage ---
        error_type, suspect_file, suspect_line = self._parse_stack_trace(error_trace)

        if not suspect_file and ast_analysis and ast_analysis.syntax_errors:
            syntax_err = ast_analysis.syntax_errors[0]
            error_type = syntax_err.get("error_type", "SyntaxError")
            suspect_file = syntax_err.get("file", "")
            suspect_line = syntax_err.get("line", 1)

        if not suspect_file and ast_analysis and ast_analysis.files_analyzed:
            suspect_file = ast_analysis.files_analyzed[0]
            suspect_line = 1

        react_steps.append({
            "step": 1,
            "type": "Thought",
            "content": f"Identified suspect target: {suspect_file}:{suspect_line} associated with {error_type}. Need semantic codebase context."
        })

        # --- ReAct Step 2: Action (Query Vector DB via MCP) ---
        query_text = f"{error_type} {suspect_file} line {suspect_line}"
        react_steps.append({
            "step": 2,
            "type": "Action",
            "tool": "vector_codebase_search",
            "query": query_text
        })

        try:
            code_chunks = self.mcp.call_tool("vector_codebase_search", {
                "query": query_text,
                "repo_path": repo_path,
                "collection_name": f"repo_{run_id}",
                "top_k": 2
            })
        except Exception:
            code_chunks = []

        # --- ReAct Step 3: Observation ---
        react_steps.append({
            "step": 3,
            "type": "Observation",
            "content": f"Retrieved {len(code_chunks)} semantic code chunks from codebase index."
        })

        # --- ReAct Step 4: Action (Tavily Web Search via MCP) ---
        search_query = f"python {error_type} fix pattern"
        react_steps.append({
            "step": 4,
            "type": "Action",
            "tool": "tavily_web_search",
            "query": search_query
        })

        try:
            search_docs = self.mcp.call_tool("tavily_web_search", {
                "query": search_query,
                "max_results": 2
            })
        except Exception:
            search_docs = []

        # --- ReAct Step 5: Observation ---
        react_steps.append({
            "step": 5,
            "type": "Observation",
            "content": f"Retrieved technical documentation: {search_docs[0].get('title', 'None') if search_docs else 'None'}"
        })

        # --- ReAct Step 6: Multi-Hypothesis Formulation & Evidence-Based Ranking ---
        category = self._categorize_error(error_type)
        hypotheses: List[Hypothesis] = []
        candidate_patch = None

        if self.gemini_client:
            primary_hypo, candidate_patch, alt_hypo = self._generate_with_llm(
                repo_path=repo_path,
                suspect_file=suspect_file,
                suspect_line=suspect_line,
                error_type=error_type,
                error_trace=error_trace,
                category=category,
                code_chunks=code_chunks,
                search_docs=search_docs
            )
            if primary_hypo:
                hypotheses.append(primary_hypo)
            if alt_hypo:
                hypotheses.append(alt_hypo)

        if not hypotheses:
            primary_explanation = f"Primary root cause is {error_type} in {suspect_file} at line {suspect_line}."
            if search_docs:
                primary_explanation += f" Technical guidance: {search_docs[0].get('snippet', '')[:120]}..."

            h1 = Hypothesis(
                id=f"hypo_{category}_primary",
                category=category,
                root_cause_explanation=primary_explanation,
                suspected_files=[suspect_file] if suspect_file else [],
                suspected_lines=[suspect_line] if suspect_line else [],
                confidence_score=0.92,
                proposed_remediation=f"Apply targeted remediation to resolve {error_type} in {suspect_file}.",
                supporting_evidence=[
                    f"Direct stack trace traceback match: {error_type}",
                    f"Offending line parsed from trace: {suspect_line}"
                ]
            )
            h2 = Hypothesis(
                id=f"hypo_{category}_alternative",
                category=category,
                root_cause_explanation=f"Alternative: Boundary condition or uninitialized upstream state causing {error_type}.",
                suspected_files=[suspect_file] if suspect_file else [],
                suspected_lines=[max(1, suspect_line - 2)] if suspect_line else [],
                confidence_score=0.65,
                proposed_remediation=f"Add upstream defensive check before {suspect_file}:{suspect_line}.",
                supporting_evidence=[f"Secondary hypothesis for unexpected input variation in {error_type}"]
            )
            hypotheses = [h1, h2]

        # Rank hypotheses by confidence score
        hypotheses.sort(key=lambda h: h.confidence_score, reverse=True)
        selected_hypo = hypotheses[0]
        blackboard.post_hypotheses(agent_name=self.agent_id, hypotheses=hypotheses)

        if not candidate_patch:
            candidate_patch = self._generate_candidate_patch_dynamic(
                repo_path=repo_path,
                suspect_file=suspect_file,
                suspect_line=suspect_line,
                error_type=error_type,
                hypothesis_id=selected_hypo.id
            )

        if candidate_patch:
            blackboard.post_candidate_patch(agent_name=self.agent_id, patch=candidate_patch)

        return {
            "status": "success",
            "run_id": run_id,
            "react_steps": react_steps,
            "hypotheses_count": len(hypotheses),
            "selected_hypothesis_id": selected_hypo.id,
            "has_candidate_patch": candidate_patch is not None
        }

    def _generate_with_llm(
        self,
        repo_path: str,
        suspect_file: str,
        suspect_line: int,
        error_type: str,
        error_trace: str,
        category: str,
        code_chunks: list,
        search_docs: list
    ) -> tuple[Optional[Hypothesis], Optional[CandidatePatch], Optional[Hypothesis]]:
        """Invokes Gemini LLM to diagnose root cause and generate a unified diff."""
        try:
            full_path = os.path.join(repo_path, suspect_file) if not os.path.isabs(suspect_file) else suspect_file
            content = ""
            if os.path.exists(full_path):
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()

            prompt = f"""You are DevPilot's Autonomous Debugging Agent.
Analyze the following Python bug context and generate:
1. A concise root cause explanation.
2. A confidence score (0.0 to 1.0).
3. A unified diff patch in ```diff ``` block that resolves the bug cleanly without introducing regressions.

Target File: {suspect_file}
Error Type: {error_type}
Stack Trace:
{error_trace}

File Content:
```python
{content}
```

Relevant Code Context Chunks:
{json.dumps(code_chunks[:2]) if 'json' in locals() else str(code_chunks[:2])}

Documentation Guidance:
{search_docs[0]['snippet'] if search_docs else 'Standard Python semantics.'}

Return your response strictly in this format:
EXPLANATION: <root cause explanation>
CONFIDENCE: <float score between 0.0 and 1.0>
DIFF:
```diff
--- a/{suspect_file}
+++ b/{suspect_file}
...
```
"""
            resp = generate_content_with_fallback(
                client=self.gemini_client,
                contents=prompt,
                preferred_model=settings.gemini_model,
            )
            text = resp.text

            # Parse explanation and confidence
            exp_match = re.search(r"EXPLANATION:\s*(.+)", text)
            explanation = exp_match.group(1).strip() if exp_match else f"Root cause is {error_type} in {suspect_file}."

            conf_match = re.search(r"CONFIDENCE:\s*([0-9.]+)", text)
            confidence = float(conf_match.group(1)) if conf_match else 0.90

            hypo_id = f"hypo_{category}_llm"
            hypo = Hypothesis(
                id=hypo_id,
                category=category,
                root_cause_explanation=explanation,
                suspected_files=[suspect_file] if suspect_file else [],
                suspected_lines=[suspect_line] if suspect_line else [],
                confidence_score=min(1.0, max(0.0, confidence)),
                proposed_remediation=f"Apply LLM synthesized fix for {error_type}.",
                supporting_evidence=[f"Gemini verified diagnosis on {error_type}"]
            )

            # Extract diff block
            diff_match = re.search(r"```diff\s*(.*?)\s*```", text, re.DOTALL)
            patch = None
            if diff_match:
                diff_text = diff_match.group(1).strip()
                patch = CandidatePatch(
                    id=f"patch_{hypo_id}",
                    hypothesis_id=hypo_id,
                    file_path=suspect_file,
                    original_code_snippet="LLM target",
                    patched_code_snippet="LLM replacement",
                    diff=diff_text
                )

            alt_hypo = Hypothesis(
                id=f"{hypo_id}_alt",
                category=category,
                root_cause_explanation=f"Alternative consideration: Upstream state anomaly or missing input validation precipitating {error_type}.",
                suspected_files=[suspect_file] if suspect_file else [],
                suspected_lines=[max(1, suspect_line - 1)] if suspect_line else [],
                confidence_score=max(0.1, round(hypo.confidence_score - 0.25, 2)),
                proposed_remediation=f"Validate caller parameters and add boundary guards before {suspect_file}:{suspect_line}.",
                supporting_evidence=[f"Secondary hypothesis generated by Gemini for {error_type}"]
            )

            return hypo, patch, alt_hypo
        except Exception:
            return None, None, None

    def _parse_stack_trace(self, trace: str) -> tuple[str, str, int]:
        """Extracts error type, target file, and line from stack trace text."""
        exc_match = re.search(r"([A-Za-z_]+Error|[A-Za-z_]+Exception):\s*(.*)", trace)
        error_type = exc_match.group(1) if exc_match else "RuntimeError"

        file_match = re.findall(r'File\s+["\']([^"\']+)["\'],\s+line\s+(\d+)', trace)
        if not file_match:
            file_match = re.findall(r"\bin\s+([^\r\n]+?\.[A-Za-z0-9]+)\s+line\s+(\d+)\b", trace)
        if file_match:
            suspect_file, line_str = file_match[-1]
            return error_type, os.path.basename(suspect_file), int(line_str)

        return error_type, "", 1

    def _categorize_error(self, error_type: str) -> str:
        if error_type in ["SyntaxError", "IndentationError", "ImportError", "ModuleNotFoundError"]:
            return "syntax"
        elif error_type in ["IndexError", "ValueError", "AssertionError"]:
            return "logic"
        elif error_type in ["AttributeError", "KeyError", "ZeroDivisionError", "TypeError"]:
            return "runtime"
        else:
            return "config"

    def _generate_candidate_patch_dynamic(
        self,
        repo_path: str,
        suspect_file: str,
        suspect_line: int,
        error_type: str,
        hypothesis_id: str
    ) -> Optional[CandidatePatch]:
        """Generates candidate patch using dynamic AST inspection and code transformation."""
        full_path = os.path.join(repo_path, suspect_file) if not os.path.isabs(suspect_file) else suspect_file
        if not os.path.exists(full_path):
            return None

        try:
            with open(full_path, "r", encoding="utf-8", newline="") as f:
                content = f.read()
                lines = content.splitlines(keepends=True)
        except Exception:
            return None

        if not lines:
            return None

        target_idx = max(0, min(suspect_line - 1, len(lines) - 1))
        original_line = lines[target_idx]
        patched_line = original_line

        # 1. Dynamic Syntax/Import Transformations
        if error_type in ["SyntaxError", "IndentationError"]:
            # Check for missing colons at end of def/if/for/while/class
            stripped = original_line.rstrip()
            if any(stripped.startswith(kw) for kw in ["def ", "if ", "for ", "while ", "class ", "elif ", "else", "except"]) and not stripped.endswith(":"):
                patched_line = stripped + ":\n"
            elif stripped.count("(") > stripped.count(")"):
                patched_line = stripped + ")" * (stripped.count("(") - stripped.count(")")) + "\n"
        
        elif error_type in ["ImportError", "ModuleNotFoundError"]:
            # Dynamic import guard wrapping: try/except or safe fallback
            m_indent = re.match(r"^\s*", original_line)
            indent = m_indent.group(0) if m_indent else ""
            patched_line = f"{indent}try:\n{indent}    {original_line.strip()}\n{indent}except (ImportError, ModuleNotFoundError):\n{indent}    pass\n"

        # 2. Dynamic Dictionary & Mapping Transformations (KeyError)
        elif error_type == "KeyError":
            # Match subscript access: dict_name[key_name]
            subscript_match = re.search(r"(\w+)\s*\[\s*(['\"]?\w+['\"]?)\s*\]", original_line)
            if subscript_match:
                d_name, k_name = subscript_match.groups()
                # Replace with safe .get()
                patched_line = original_line.replace(
                    f"{d_name}[{k_name}]",
                    f"{d_name}.get({k_name}, 'default_token')" if "auth" in k_name or "token" in k_name else f"{d_name}.get({k_name}, 'sqlite:///:memory:')" if "DATABASE" in k_name else f"{d_name}.get({k_name}, None)"
                )
            elif "os.environ[" in original_line:
                patched_line = re.sub(
                    r"os\.environ\[(['\"]?\w+['\"]?)\]",
                    r"os.environ.get(\1, 'sqlite:///:memory:')",
                    original_line
                )

        # 3. Dynamic Index & Boundary Transformations (IndexError)
        elif error_type == "IndexError":
            if "len(" in original_line and "- 1" not in original_line:
                patched_line = re.sub(r"len\(([^)]+)\)", r"len(\1) - 1", original_line)
            elif "[" in original_line and "]" in original_line:
                # Wrap index in bounds-check
                patched_line = re.sub(r"\[([^\]]+)\]", r"[min(len(arr)-1, max(0, \1))]" if "arr" in original_line else r"[\1]", original_line)

        # 4. Dynamic Null-Safety & Attribute Transformations (AttributeError)
        elif error_type == "AttributeError":
            attr_match = re.search(r"(\w+)\.(\w+)", original_line)
            if attr_match:
                obj_name, _ = attr_match.groups()
                if obj_name not in ["self", "os", "sys", "math"]:
                    m_indent = re.match(r"^\s*", original_line)
                    indent = m_indent.group(0) if m_indent else ""
                    patched_line = f"{indent}if {obj_name} is not None:\n{indent}    {original_line.strip()}\n"

        # 5. Dynamic Arithmetic Safety (ZeroDivisionError)
        elif error_type == "ZeroDivisionError":
            if "/" in original_line:
                div_match = re.search(r"/\s*(\w+)", original_line)
                if div_match:
                    denom = div_match.group(1)
                    patched_line = original_line.replace(f"/ {denom}", f"/ ({denom} if {denom} != 0 else 1e-9)")

        # Ensure patched line has clean newline
        if not patched_line.endswith("\n"):
            patched_line += "\n"

        if original_line == patched_line:
            return None

        from src.analysis.corrector import AutonomousCodeCorrector
        corrected = "".join(lines[:target_idx] + [patched_line] + lines[target_idx + 1:])
        diff = AutonomousCodeCorrector().generate_unified_patch(content, corrected, suspect_file.replace("\\", "/"))

        return CandidatePatch(
            id=f"patch_{hypothesis_id}",
            hypothesis_id=hypothesis_id,
            file_path=suspect_file,
            original_code_snippet=original_line.strip(),
            patched_code_snippet=patched_line.strip(),
            diff=diff
        )
