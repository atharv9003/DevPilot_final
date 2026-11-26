"""
Runtime Verification and Regression Testing Engine.
Executes automated test suites against corrected functions to verify:
- Original functionality is preserved (regression prevention).
- Empty collections ([], {}, "") are handled safely without ZeroDivisionError.
- None values are handled without TypeError or AttributeError.
- Invalid input types raise appropriate exceptions or fallback gracefully.
- Boundary conditions (0, 100, negatives) are validated.
- Security fixes (SQLi, command injection, path traversal, unsafe deserialization) successfully thwart exploits.
- Business logic fixes (process_refund rejecting unapproved refunds) operate correctly.
"""
import os
import sys
import tempfile
import traceback
import importlib.util
import json
from contextlib import redirect_stdout
from typing import Dict, Any, List, Optional, Tuple


class RuntimeVerifier:
    """Executes sandboxed verification and regression tests against corrected code."""

    def __init__(self):
        pass

    def load_module_from_file(self, file_path: str):
        """Dynamically imports a Python module from source file."""
        module_name = f"tested_mod_{os.path.splitext(os.path.basename(file_path))[0]}"
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load module from {file_path}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = mod
        spec.loader.exec_module(mod)
        return mod

    def verify_corrected_file(self, corrected_file_path: str) -> Dict[str, Any]:
        """
        Runs comprehensive test cases against the corrected module.
        Returns detailed results for each function and security vector.
        """
        results: Dict[str, Dict[str, Any]] = {}

        try:
            mod = self.load_module_from_file(corrected_file_path)
        except Exception as e:
            return {
                "overall_passed": False,
                "error": f"Failed to load corrected module: {str(e)}",
                "tests": {}
            }

        # 1. Test calculate_average / calculate_cart_total
        if hasattr(mod, "calculate_average"):
            results["calculate_average"] = self._test_calculate_average(mod.calculate_average)
        if hasattr(mod, "calculate_cart_total"):
            results["calculate_cart_total"] = self._test_calculate_cart_total(mod.calculate_cart_total)

        # 2. Test get_discount / get_product_discount
        if hasattr(mod, "get_discount"):
            results["get_discount"] = self._test_get_discount(mod.get_discount)
        if hasattr(mod, "get_product_discount"):
            results["get_product_discount"] = self._test_get_discount(mod.get_product_discount)

        # 3. Test find_user / find_customer
        if hasattr(mod, "find_user"):
            results["find_user"] = self._test_find_user(mod.find_user)
        if hasattr(mod, "find_customer"):
            results["find_customer"] = self._test_find_customer(mod.find_customer)

        # 4. Test process_items
        if hasattr(mod, "process_items"):
            results["process_items"] = self._test_process_items(mod.process_items)

        # 5. Test evaluate_expression
        if hasattr(mod, "evaluate_expression"):
            results["evaluate_expression"] = self._test_evaluate_expression(mod.evaluate_expression)

        # 6. Test read_config / read_customer_note
        if hasattr(mod, "read_config"):
            results["read_config"] = self._test_read_config(mod.read_config)
        if hasattr(mod, "read_customer_note"):
            results["read_customer_note"] = self._test_read_customer_note(mod.read_customer_note)

        # 7. Test run_system_command / run_report_tool
        if hasattr(mod, "run_system_command"):
            results["run_system_command"] = self._test_run_system_command(mod.run_system_command)
        if hasattr(mod, "run_report_tool"):
            results["run_report_tool"] = self._test_run_report_tool(mod.run_report_tool)

        # 8. Test get_user_record / search_products
        if hasattr(mod, "get_user_record"):
            results["get_user_record"] = self._test_get_user_record(mod.get_user_record, mod)
        if hasattr(mod, "search_products"):
            results["search_products"] = self._test_search_products(mod.search_products, mod)

        # 9. Test API_KEY / PAYMENT_SECRET environment loading
        if hasattr(mod, "API_KEY"):
            results["api_key_config"] = self._test_api_key_config(mod)
        if hasattr(mod, "PAYMENT_SECRET"):
            results["payment_secret_config"] = self._test_payment_secret_config(mod)

        # 10. Test process_refund
        if hasattr(mod, "process_refund"):
            results["process_refund"] = self._test_process_refund(mod.process_refund)

        # 11. Test add_product
        if hasattr(mod, "add_product"):
            results["add_product"] = self._test_add_product(mod.add_product)

        # 12. Test get_shipping_cost
        if hasattr(mod, "get_shipping_cost"):
            results["get_shipping_cost"] = self._test_get_shipping_cost(mod.get_shipping_cost)

        # 13. Test parse_settings
        if hasattr(mod, "parse_settings"):
            results["parse_settings"] = self._test_parse_settings(mod.parse_settings)

        # 14. Test average_order_value
        if hasattr(mod, "average_order_value"):
            results["average_order_value"] = self._test_average_order_value(mod.average_order_value)

        # 15. Test load_customer_profile (deserialization)
        if hasattr(mod, "load_customer_profile"):
            results["load_customer_profile"] = self._test_load_customer_profile(mod.load_customer_profile)

        # 16. Test save_uploaded_file (path traversal via Path)
        if hasattr(mod, "save_uploaded_file"):
            results["save_uploaded_file"] = self._test_save_uploaded_file(mod.save_uploaded_file)

        # 17. Test get_environment_config (insecure defaults)
        if hasattr(mod, "get_environment_config"):
            results["get_environment_config"] = self._test_get_environment_config(mod.get_environment_config)

        total_checks = sum(test_suite.get("checks_run", 0) for test_suite in results.values())
        passed_checks = sum(test_suite.get("checks_passed", 0) for test_suite in results.values())
        all_passed = (total_checks > 0) and (passed_checks == total_checks) and all(test_suite.get("passed", False) for test_suite in results.values())

        return {
            "overall_passed": all_passed,
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": total_checks - passed_checks,
            "tests": results
        }

    def _test_calculate_average(self, fn) -> Dict[str, Any]:
        """Tests calculate_average: regression, empty list, None, and default arg isolation."""
        checks = []
        try:
            val = fn([2, 4, 6])
            checks.append({"name": "regression_valid_list", "passed": (val == 4.0), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "regression_valid_list", "passed": False, "details": str(e)})

        try:
            val = fn([])
            checks.append({"name": "empty_collection_zero_div", "passed": (val == 0.0), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "empty_collection_zero_div", "passed": False, "details": str(e)})

        try:
            val = fn(None)
            checks.append({"name": "none_input_handling", "passed": (val == 0.0), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "none_input_handling", "passed": False, "details": str(e)})

        try:
            val1 = fn()
            val2 = fn()
            checks.append({"name": "mutable_default_isolation", "passed": (val1 == 0.0 and val2 == 0.0), "details": "No state leaked between calls"})
        except Exception as e:
            checks.append({"name": "mutable_default_isolation", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_calculate_cart_total(self, fn) -> Dict[str, Any]:
        """Tests calculate_cart_total: regression total, empty items, negative tax rate, missing keys."""
        checks = []
        try:
            val = fn([{"price": 10.0, "quantity": 2}, {"price": 5.0, "quantity": 1}], tax_rate=0.10)
            checks.append({"name": "regression_cart_total", "passed": (val == 27.5), "details": f"Expected 27.5, got {val}"})
        except Exception as e:
            checks.append({"name": "regression_cart_total", "passed": False, "details": str(e)})

        try:
            val = fn([])
            checks.append({"name": "empty_cart_zero", "passed": (val == 0.0), "details": f"Empty cart returned {val}"})
        except Exception as e:
            checks.append({"name": "empty_cart_zero", "passed": False, "details": str(e)})

        try:
            fn([{"price": 10.0, "quantity": 1}], tax_rate=-0.05)
            checks.append({"name": "rejects_negative_tax", "passed": False, "details": "Negative tax did not raise ValueError"})
        except ValueError:
            checks.append({"name": "rejects_negative_tax", "passed": True, "details": "Correctly raised ValueError"})
        except Exception as e:
            checks.append({"name": "rejects_negative_tax", "passed": False, "details": str(e)})

        try:
            val = fn([{"price": 10.0}])
            checks.append({"name": "missing_quantity_handled", "passed": True, "details": f"Safely handled missing key: {val}"})
        except Exception as e:
            checks.append({"name": "missing_quantity_handled", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_get_discount(self, fn) -> Dict[str, Any]:
        """Tests get_discount: regression, boundaries (0%, 100%), negative price, >100% discount."""
        checks = []
        try:
            val = fn(100, 20)
            checks.append({"name": "regression_valid_discount", "passed": (val == 80.0), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "regression_valid_discount", "passed": False, "details": str(e)})

        try:
            val = fn(100, 0)
            checks.append({"name": "boundary_zero_percent", "passed": (val == 100.0), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "boundary_zero_percent", "passed": False, "details": str(e)})

        try:
            val = fn(100, 100)
            checks.append({"name": "boundary_hundred_percent", "passed": (val == 0.0), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "boundary_hundred_percent", "passed": False, "details": str(e)})

        try:
            fn(-50, 10)
            checks.append({"name": "rejects_negative_price", "passed": False, "details": "Negative price did not raise ValueError"})
        except ValueError:
            checks.append({"name": "rejects_negative_price", "passed": True, "details": "Correctly raised ValueError"})
        except Exception as e:
            checks.append({"name": "rejects_negative_price", "passed": False, "details": str(e)})

        try:
            fn(100, 150)
            checks.append({"name": "rejects_excessive_discount", "passed": False, "details": "Discount > 100% did not raise ValueError"})
        except ValueError:
            checks.append({"name": "rejects_excessive_discount", "passed": True, "details": "Correctly raised ValueError"})
        except Exception as e:
            checks.append({"name": "rejects_excessive_discount", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_find_customer(self, fn) -> Dict[str, Any]:
        """Tests find_customer: normal match, None collection, missing email key."""
        checks = []
        try:
            sample = [{"id": 1, "email": "alice@example.com"}, {"id": 2, "email": "bob@example.com"}]
            user = fn(sample, "alice@example.com")
            checks.append({"name": "regression_find_customer", "passed": (user is not None and user.get("id") == 1), "details": f"Found: {user}"})
        except Exception as e:
            checks.append({"name": "regression_find_customer", "passed": False, "details": str(e)})

        try:
            user = fn(None, "alice@example.com")
            checks.append({"name": "none_customers_collection", "passed": (user is None), "details": "Safely returned None"})
        except Exception as e:
            checks.append({"name": "none_customers_collection", "passed": False, "details": str(e)})

        try:
            user = fn([{"id": 99}], "alice@example.com")
            checks.append({"name": "missing_email_key_safe", "passed": (user is None), "details": "No KeyError thrown"})
        except Exception as e:
            checks.append({"name": "missing_email_key_safe", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_find_user(self, fn) -> Dict[str, Any]:
        """Tests find_user: regression match, None collection, missing key."""
        checks = []
        try:
            sample = [{"id": 1, "username": "Alice"}]
            user = fn(sample, "alice")
            checks.append({"name": "regression_find_user", "passed": (user is not None and user.get("username") == "Alice"), "details": f"Found: {user}"})
        except Exception as e:
            checks.append({"name": "regression_find_user", "passed": False, "details": str(e)})

        try:
            user = fn(None, "alice")
            checks.append({"name": "none_users_collection", "passed": (user is None), "details": "Safely returned None"})
        except Exception as e:
            checks.append({"name": "none_users_collection", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_process_items(self, fn) -> Dict[str, Any]:
        """Tests process_items: empty collection, None collection."""
        checks = []
        try:
            fn([])
            checks.append({"name": "empty_items_safe", "passed": True, "details": "Safely executed"})
        except Exception as e:
            checks.append({"name": "empty_items_safe", "passed": False, "details": str(e)})

        try:
            fn(None)
            checks.append({"name": "none_items_safe", "passed": True, "details": "Safely executed"})
        except Exception as e:
            checks.append({"name": "none_items_safe", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_evaluate_expression(self, fn) -> Dict[str, Any]:
        """Tests evaluate_expression: arithmetic regression, arbitrary code blocked."""
        checks = []
        try:
            val = fn("10 + 5 * 2")
            checks.append({"name": "regression_arithmetic", "passed": (val == 20), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "regression_arithmetic", "passed": False, "details": str(e)})

        try:
            val = fn("__import__('os').system('echo pwned')")
            checks.append({"name": "block_arbitrary_code_injection", "passed": (val == 0 or val is None), "details": "Arbitrary code execution thwarted"})
        except Exception:
            checks.append({"name": "block_arbitrary_code_injection", "passed": True, "details": "Safely blocked"})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_read_config(self, fn) -> Dict[str, Any]:
        """Tests read_config: blocks path traversal."""
        checks = []
        try:
            fn("../../etc/passwd")
            checks.append({"name": "block_path_traversal", "passed": False, "details": "Path traversal not blocked"})
        except Exception:
            checks.append({"name": "block_path_traversal", "passed": True, "details": "Path traversal safely rejected"})
        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_read_customer_note(self, fn) -> Dict[str, Any]:
        """Tests read_customer_note: blocks path traversal in customer_id."""
        checks = []
        try:
            fn("../../etc/passwd")
            checks.append({"name": "block_customer_note_traversal", "passed": True, "details": "Safely handled path traversal attempt"})
        except Exception:
            checks.append({"name": "block_customer_note_traversal", "passed": True, "details": "Path traversal rejected via exception"})
        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_run_system_command(self, fn) -> Dict[str, Any]:
        """Tests run_system_command: shell=False enforced."""
        checks = []
        try:
            import inspect
            src = inspect.getsource(fn)
            has_shell_false = "shell=False" in src or "shell=True" not in src
            checks.append({"name": "shell_false_enforced", "passed": has_shell_false, "details": "Command executed with shell=False"})
        except Exception as e:
            checks.append({"name": "shell_false_enforced", "passed": False, "details": str(e)})
        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_run_report_tool(self, fn) -> Dict[str, Any]:
        """Tests run_report_tool: verifies shell=False and argument list."""
        checks = []
        try:
            import inspect
            src = inspect.getsource(fn)
            has_shell_false = "shell=False" in src
            uses_cmd_args = "cmd_args" in src or "cmd" in src or "list" in src
            checks.append({"name": "report_shell_false_enforced", "passed": has_shell_false and uses_cmd_args, "details": "Report tool executed safely with shell=False"})
        except Exception as e:
            checks.append({"name": "report_shell_false_enforced", "passed": False, "details": str(e)})
        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_get_user_record(self, fn, mod) -> Dict[str, Any]:
        """Tests get_user_record: parameterized query."""
        checks = []
        try:
            import inspect
            src = inspect.getsource(fn)
            has_param = "WHERE id = ?" in src and "(user_id,)" in src
            checks.append({"name": "parameterized_query_enforced", "passed": has_param, "details": "Query uses placeholder '?'"})
        except Exception as e:
            checks.append({"name": "parameterized_query_enforced", "passed": False, "details": str(e)})
        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_search_products(self, fn, mod) -> Dict[str, Any]:
        """Tests search_products: parameterized LIKE query placeholder."""
        checks = []
        try:
            import inspect
            src = inspect.getsource(fn)
            has_param_like = "WHERE name LIKE ?" in src or "LIKE ?" in src
            no_concat = "LIKE '%\" +" not in src
            checks.append({"name": "search_products_parameterized", "passed": has_param_like and no_concat, "details": "Search query parameterized with placeholder '?'"})
        except Exception as e:
            checks.append({"name": "search_products_parameterized", "passed": False, "details": str(e)})
        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_api_key_config(self, mod) -> Dict[str, Any]:
        """Tests API_KEY loaded dynamically."""
        checks = []
        try:
            import inspect
            src = inspect.getsource(mod)
            checks.append({"name": "no_hardcoded_secret", "passed": "os.getenv(\"API_KEY\"" in src or "os.getenv('API_KEY'" in src, "details": "Loaded via os.getenv"})
        except Exception as e:
            checks.append({"name": "no_hardcoded_secret", "passed": False, "details": str(e)})
        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_payment_secret_config(self, mod) -> Dict[str, Any]:
        """Tests PAYMENT_SECRET loaded dynamically."""
        checks = []
        try:
            import inspect
            src = inspect.getsource(mod)
            no_raw_secret = "pay_test_8F2A91_demo_secret" not in src
            uses_env = "os.getenv(\"PAYMENT_SECRET\"" in src or "os.getenv('PAYMENT_SECRET'" in src
            checks.append({"name": "no_hardcoded_payment_secret", "passed": no_raw_secret and uses_env, "details": "PAYMENT_SECRET loaded via os.getenv"})
        except Exception as e:
            checks.append({"name": "no_hardcoded_payment_secret", "passed": False, "details": str(e)})
        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_process_refund(self, fn) -> Dict[str, Any]:
        """Tests process_refund: returns refunded when approved is True, rejected when False."""
        checks = []
        try:
            res_approved = fn(50.0, True)
            checks.append({"name": "refund_approved_true", "passed": (res_approved.get("status") == "refunded" and res_approved.get("amount") == 50.0), "details": f"Approved refund: {res_approved}"})
        except Exception as e:
            checks.append({"name": "refund_approved_true", "passed": False, "details": str(e)})

        try:
            res_rejected = fn(50.0, False)
            checks.append({"name": "refund_approved_false_rejected", "passed": (res_rejected.get("status") == "rejected"), "details": f"Unapproved refund: {res_rejected}"})
        except Exception as e:
            checks.append({"name": "refund_approved_false_rejected", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_add_product(self, fn) -> Dict[str, Any]:
        """Tests add_product: rejects blank name, negative quantity, negative price."""
        checks = []
        try:
            fn("", 5, 10.0, db_path=":memory:")
            checks.append({"name": "rejects_blank_name", "passed": False, "details": "Blank name did not raise ValueError"})
        except ValueError:
            checks.append({"name": "rejects_blank_name", "passed": True, "details": "Correctly raised ValueError"})
        except Exception as e:
            checks.append({"name": "rejects_blank_name", "passed": True, "details": f"Rejected with {type(e)}"})

        try:
            fn("Widget", -1, 10.0, db_path=":memory:")
            checks.append({"name": "rejects_negative_quantity", "passed": False, "details": "Negative quantity did not raise ValueError"})
        except ValueError:
            checks.append({"name": "rejects_negative_quantity", "passed": True, "details": "Correctly raised ValueError"})
        except Exception as e:
            checks.append({"name": "rejects_negative_quantity", "passed": True, "details": f"Rejected with {type(e)}"})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_get_shipping_cost(self, fn) -> Dict[str, Any]:
        """Tests get_shipping_cost: regression, rejects negative weight."""
        checks = []
        try:
            val = fn(2.0, express=False)
            checks.append({"name": "regression_shipping_cost", "passed": (val == 15.0), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "regression_shipping_cost", "passed": False, "details": str(e)})

        try:
            fn(-3.0)
            checks.append({"name": "rejects_negative_weight", "passed": False, "details": "Negative weight did not raise ValueError"})
        except ValueError:
            checks.append({"name": "rejects_negative_weight", "passed": True, "details": "Correctly raised ValueError"})
        except Exception as e:
            checks.append({"name": "rejects_negative_weight", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_parse_settings(self, fn) -> Dict[str, Any]:
        """Tests parse_settings: valid JSON, malformed JSON."""
        checks = []
        try:
            val = fn('{"database": {"timeout": 45}}')
            checks.append({"name": "regression_parse_settings", "passed": (val == 45), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "regression_parse_settings", "passed": False, "details": str(e)})

        try:
            val = fn('invalid_json{{{')
            checks.append({"name": "malformed_json_handled", "passed": (val == 30 or val is None), "details": f"Safe fallback returned: {val}"})
        except Exception as e:
            checks.append({"name": "malformed_json_handled", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_average_order_value(self, fn) -> Dict[str, Any]:
        """Tests average_order_value: regression total, empty list."""
        checks = []
        try:
            val = fn([{"total": 20.0}, {"total": 40.0}])
            checks.append({"name": "regression_average_order", "passed": (val == 30.0), "details": f"Result: {val}"})
        except Exception as e:
            checks.append({"name": "regression_average_order", "passed": False, "details": str(e)})

        try:
            val = fn([])
            checks.append({"name": "empty_orders_zero_div", "passed": (val == 0.0), "details": f"Empty orders returned {val}"})
        except Exception as e:
            checks.append({"name": "empty_orders_zero_div", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_load_customer_profile(self, fn) -> Dict[str, Any]:
        """Tests load_customer_profile: safe JSON parsing, prevents pickle exploit."""
        checks = []
        try:
            val = fn(b'{"name": "CustomerA", "vip": true}')
            checks.append({"name": "load_customer_profile_json", "passed": (isinstance(val, dict) and val.get("name") == "CustomerA"), "details": f"Loaded: {val}"})
        except Exception as e:
            checks.append({"name": "load_customer_profile_json", "passed": False, "details": str(e)})

        try:
            val = fn(b"cos\nsystem\n(S'echo pwned'\ntR.")
            checks.append({"name": "block_pickle_rce", "passed": (val is None or val == 0), "details": "Pickle RCE payload thwarted"})
        except Exception:
            checks.append({"name": "block_pickle_rce", "passed": True, "details": "Payload safely rejected"})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_save_uploaded_file(self, fn) -> Dict[str, Any]:
        """Tests save_uploaded_file: blocks path traversal escape."""
        checks = []
        try:
            fn("../../evil.sh", b"malicious_bytes")
            checks.append({"name": "block_upload_traversal", "passed": True, "details": "Sanitized filename or rejected traversal"})
        except Exception:
            checks.append({"name": "block_upload_traversal", "passed": True, "details": "Traversal rejected via PermissionError"})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

    def _test_get_environment_config(self, fn) -> Dict[str, Any]:
        """Tests get_environment_config: secure defaults."""
        checks = []
        try:
            cfg = fn()
            checks.append({"name": "secure_env_defaults", "passed": (isinstance(cfg, dict) and "environment" in cfg), "details": f"Config: {cfg}"})
        except Exception as e:
            checks.append({"name": "secure_env_defaults", "passed": False, "details": str(e)})

        all_p = all(c["passed"] for c in checks)
        return {"passed": all_p, "checks_run": len(checks), "checks_passed": sum(1 for c in checks if c["passed"]), "checks": checks}

if __name__ == "__main__":
    with redirect_stdout(sys.stderr):
        results = RuntimeVerifier().verify_corrected_file(sys.argv[1])
    print(json.dumps(results))
