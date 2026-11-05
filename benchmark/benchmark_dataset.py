"""
Curated 40-Run Empirical Benchmark Dataset
Specifies 40 reproducible Python bug scenarios across 4 failure categories:
1. Syntax & Import Errors (10 scenarios)
2. Algorithmic Logic Defects (10 scenarios)
3. Runtime Exceptions (10 scenarios)
4. Environment & Config Faults (10 scenarios)
"""
from typing import List
from pydantic import BaseModel


class BenchmarkScenario(BaseModel):
    id: str
    category: str
    name: str
    description: str
    stack_trace: str
    persona: str  # 'constructive', 'stressed', 'adversarial'
    architecture: str  # 'hierarchical' or 'sequential'
    code_filename: str
    code_content: str
    test_filename: str
    test_content: str
    ground_truth_root_cause: str


def get_all_40_scenarios() -> List[BenchmarkScenario]:
    scenarios: List[BenchmarkScenario] = []

    # ==========================================
    # Category 1: Syntax & Import Errors (10 runs)
    # Persona: Constructive Developer | Arch: Hierarchical (ReAct)
    # ==========================================
    for i in range(1, 11):
        scenarios.append(BenchmarkScenario(
            id=f"SYNTAX_{i:02d}",
            category="syntax",
            name=f"Syntax & Import Scenario #{i}",
            description=f"Syntax or package import failure in data processing module {i}.",
            stack_trace=f'File "parser_{i}.py", line 4\n    from modules import helper_{i}\nImportError: cannot import name helper_{i} due to circular dependency',
            persona="constructive",
            architecture="hierarchical",
            code_filename=f"parser_{i}.py",
            code_content=(
                f"# parser_{i}.py\n"
                f"from modules import helper_{i}\n\n"
                f"def process_data_{i}(x):\n"
                f"    return x * 2\n"
            ),
            test_filename=f"test_parser_{i}.py",
            test_content=(
                f"from parser_{i} import process_data_{i}\n\n"
                f"def test_process():\n"
                f"    assert process_data_{i}(5) == 10\n"
            ),
            ground_truth_root_cause="ImportError / Circular Import"
        ))

    # ==========================================
    # Category 2: Algorithmic Logic Defects (10 runs)
    # Persona: Stressed / Frustrated Senior Dev | Arch: Hierarchical (ReAct)
    # ==========================================
    for i in range(1, 11):
        scenarios.append(BenchmarkScenario(
            id=f"LOGIC_{i:02d}",
            category="logic",
            name=f"Algorithmic Logic Defect #{i}",
            description=f"Boundary condition and off-by-one error in search/sort index {i}.",
            stack_trace=f'File "algo_{i}.py", line 5, in search_item_{i}\n    return arr[high]\nIndexError: list index out of range',
            persona="stressed",
            architecture="hierarchical",
            code_filename=f"algo_{i}.py",
            code_content=(
                f"# algo_{i}.py\n"
                f"def search_item_{i}(arr, target):\n"
                f"    if not arr: return -1\n"
                f"    high = len(arr)\n"
                f"    return arr[high] if arr[high] == target else -1\n"
            ),
            test_filename=f"test_algo_{i}.py",
            test_content=(
                f"from algo_{i} import search_item_{i}\n\n"
                f"def test_search():\n"
                f"    assert search_item_{i}([10, 20, 30], 30) == 30\n"
                f"    assert search_item_{i}([10, 20, 30], 99) == -1\n"
            ),
            ground_truth_root_cause="IndexError / Off-by-one boundary"
        ))

    # ==========================================
    # Category 3: Runtime Exceptions (10 runs)
    # Persona: Adversarial Injection Persona | Arch: Hierarchical (ReAct)
    # ==========================================
    for i in range(1, 11):
        scenarios.append(BenchmarkScenario(
            id=f"RUNTIME_{i:02d}",
            category="runtime",
            name=f"Runtime Exception #{i}",
            description=f"Unhandled NoneType and KeyError in authentication & payload parser {i}.",
            stack_trace=f'File "handler_{i}.py", line 4, in parse_payload_{i}\n    token = payload["auth_token"]\nKeyError: \'auth_token\'',
            persona="adversarial",
            architecture="hierarchical",
            code_filename=f"handler_{i}.py",
            code_content=(
                f"# handler_{i}.py\n"
                f"def parse_payload_{i}(payload):\n"
                f"    token = payload[\"auth_token\"]\n"
                f"    return f'valid:{{token}}'\n"
            ),
            test_filename=f"test_handler_{i}.py",
            test_content=(
                f"from handler_{i} import parse_payload_{i}\n\n"
                f"def test_payload():\n"
                f"    assert parse_payload_{i}({{'auth_token': 'secret'}}) == 'valid:secret'\n"
                f"    assert parse_payload_{i}({{}}) == 'valid:default_token'\n"
            ),
            ground_truth_root_cause="KeyError / Unhandled Dictionary Key"
        ))

    # ==========================================
    # Category 4: Environment & Config Faults (10 runs)
    # Architecture: Sequential vs ReAct comparison | Persona: Multi-Prompt Variance
    # ==========================================
    for i in range(1, 11):
        arch = "hierarchical" if (i % 2 == 1) else "sequential"
        persona = "constructive" if i <= 4 else ("stressed" if i <= 7 else "adversarial")
        scenarios.append(BenchmarkScenario(
            id=f"CONFIG_{i:02d}",
            category="config",
            name=f"Config & Environment Fault #{i}",
            description=f"Relative file path resolution and missing environment variable {i}.",
            stack_trace=f'File "config_{i}.py", line 4, in get_database_uri_{i}\n    return os.environ["DATABASE_URL_{i}"]\nKeyError: \'DATABASE_URL_{i}\'',
            persona=persona,
            architecture=arch,
            code_filename=f"config_{i}.py",
            code_content=(
                f"# config_{i}.py\n"
                f"import os\n"
                f"def get_database_uri_{i}():\n"
                f"    return os.environ[\"DATABASE_URL_{i}\"]\n"
            ),
            test_filename=f"test_config_{i}.py",
            test_content=(
                f"from config_{i} import get_database_uri_{i}\n\n"
                f"def test_uri():\n"
                f"    assert 'sqlite' in get_database_uri_{i}()\n"
            ),
            ground_truth_root_cause="KeyError / Environment Variable Missing"
        ))

    return scenarios
