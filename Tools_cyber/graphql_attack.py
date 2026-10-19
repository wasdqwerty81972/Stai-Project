from typing import Any, Dict, List
from cyber_tools import CyberToolPlugin, RiskLevel
import json
import requests
import time


class GraphQLAttackTool(CyberToolPlugin):
    """GraphQL attack testing - batching, aliasing, DoS, field duplication."""
    name = "graphql_attack"
    description = "Test GraphQL vulnerabilities: batching, aliasing, deep queries, field duplication, directive abuse"
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        url = arguments.get("url", "")
        headers = arguments.get("headers", {})
        tests = arguments.get("tests", ["batching", "aliasing", "deep_query", "field_duplication", "directive_overloading"])
        timeout = arguments.get("timeout", 30)

        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}

        results = {}

        try:
            # Test 1: Query Batching
            if "batching" in tests:
                results["batching"] = self._test_batching(url, headers, timeout)

            # Test 2: Alias Overloading
            if "aliasing" in tests:
                results["aliasing"] = self._test_aliasing(url, headers, timeout)

            # Test 3: Deep Query / Recursion
            if "deep_query" in tests:
                results["deep_query"] = self._test_deep_query(url, headers, timeout)

            # Test 4: Field Duplication
            if "field_duplication" in tests:
                results["field_duplication"] = self._test_field_duplication(url, headers, timeout)

            # Test 5: Directive Overloading
            if "directive_overloading" in tests:
                results["directive_overloading"] = self._test_directive_overloading(url, headers, timeout)

            # Test 6: Query Cost / Complexity
            if "cost_analysis" in tests:
                results["cost_analysis"] = self._test_cost_analysis(url, headers, timeout)

            vulnerable = any(r.get("vulnerable", False) for r in results.values())

            return {
                "success": True,
                "output": {
                    "url": url,
                    "tests_run": list(results.keys()),
                    "vulnerable": vulnerable,
                    "results": results
                },
                "error": ""
            }
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}

    def _send_query(self, url: str, headers: Dict, query: Any, timeout: int) -> Dict:
        """Send GraphQL query and return response info."""
        start = time.time()
        try:
            resp = requests.post(
                url,
                json=query if isinstance(query, dict) else {"query": query},
                headers={"Content-Type": "application/json", **headers},
                timeout=timeout
            )
            elapsed = time.time() - start
            return {
                "status_code": resp.status_code,
                "response_time": elapsed,
                "body": resp.text[:2000],
                "json": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else None
            }
        except requests.Timeout:
            return {"status_code": 0, "response_time": timeout, "error": "timeout"}
        except Exception as e:
            return {"status_code": 0, "response_time": time.time() - start, "error": str(e)}

    def _test_batching(self, url: str, headers: Dict, timeout: int) -> Dict:
        """Test batch query support (multiple queries in one request)."""
        batch_query = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        result = self._send_query(url, headers, batch_query, timeout)
        
        vulnerable = False
        details = ""
        if result.get("status_code") == 200:
            try:
                data = result.get("json", [])
                if isinstance(data, list) and len(data) == 3:
                    vulnerable = True
                    details = "Batch queries accepted - returned 3 responses"
            except:
                pass
        
        return {"vulnerable": vulnerable, "details": details, "response": result}

    def _test_aliasing(self, url: str, headers: Dict, timeout: int) -> Dict:
        """Test alias overloading (many aliases for same field)."""
        # Create query with 100 aliases
        aliases = " ".join([f"a{i}: __typename" for i in range(100)])
        query = f"query AliasTest {{ {aliases} }}"
        result = self._send_query(url, headers, query, timeout)
        
        vulnerable = False
        details = ""
        if result.get("status_code") == 200:
            try:
                data = result.get("json", {}).get("data", {})
                if len(data) >= 50:  # Accepted many aliases
                    vulnerable = True
                    details = f"Alias overloading accepted - returned {len(data)} aliases"
            except:
                pass
        
        return {"vulnerable": vulnerable, "details": details, "response": result}

    def _test_deep_query(self, url: str, headers: Dict, timeout: int) -> Dict:
        """Test deep nested query (recursion DoS)."""
        # Build deeply nested query (15 levels)
        def build_deep(depth: int) -> str:
            if depth <= 0:
                return "__typename"
            return f"{{ node {{ {build_deep(depth - 1)} }} }}"
        
        query = f"query DeepQuery {{ {build_deep(15)} }}"
        result = self._send_query(url, headers, query, timeout)
        
        vulnerable = False
        details = ""
        if result.get("status_code") == 200:
            try:
                data = result.get("json", {})
                if "errors" not in data or not data.get("errors"):
                    vulnerable = True
                    details = "Deep query (15 levels) accepted without depth limiting"
            except:
                pass
        
        return {"vulnerable": vulnerable, "details": details, "response": result}

    def _test_field_duplication(self, url: str, headers: Dict, timeout: int) -> Dict:
        """Test duplicate field exploitation."""
        # Repeat same field 100 times
        fields = " ".join(["__typename"] * 100)
        query = f"query DuplicateFields {{ {fields} }}"
        result = self._send_query(url, headers, query, timeout)
        
        vulnerable = False
        details = ""
        if result.get("status_code") == 200:
            try:
                data = result.get("json", {}).get("data", {})
                if len(data) >= 50:
                    vulnerable = True
                    details = "Field duplication accepted - no query complexity limits"
            except:
                pass
        
        return {"vulnerable": vulnerable, "details": details, "response": result}

    def _test_directive_overloading(self, url: str, headers: Dict, timeout: int) -> Dict:
        """Test @skip/@include directive abuse."""
        # Many directives
        directives = " ".join([f"@skip(if: false)" for _ in range(50)])
        query = f"query DirectiveTest {{ __typename {directives} }}"
        result = self._send_query(url, headers, query, timeout)
        
        vulnerable = False
        details = ""
        if result.get("status_code") == 200:
            vulnerable = True
            details = "Directive overloading accepted"
        
        return {"vulnerable": vulnerable, "details": details, "response": result}

    def _test_cost_analysis(self, url: str, headers: Dict, timeout: int) -> Dict:
        """Test if query cost/complexity analysis is enforced."""
        # Very expensive query
        query = """
        query CostTest {
            __typename
            ... on Query {
                """ + " ".join([f"field{i}: __typename" for i in range(200)]) + """
            }
        }
        """
        result = self._send_query(url, headers, query, timeout)
        
        vulnerable = False
        details = ""
        if result.get("status_code") == 200:
            try:
                data = result.get("json", {})
                if "errors" not in data or not any("complexity" in str(e).lower() or "cost" in str(e).lower() for e in data.get("errors", [])):
                    vulnerable = True
                    details = "No query cost/complexity limiting detected"
            except:
                pass
        
        return {"vulnerable": vulnerable, "details": details, "response": result}


TOOL_CLASS = GraphQLAttackTool