from typing import Any, Dict, List
from cyber_tools import CyberToolPlugin, RiskLevel
import json
import requests
import re


class GraphQLIntrospectionTool(CyberToolPlugin):
    """GraphQL introspection and schema enumeration - READ_ONLY."""
    name = "graphql_introspection"
    description = "Perform GraphQL introspection query to enumerate schema, types, fields, and directives"
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                kind
                name
                description
                fields(includeDeprecated: true) {
                    name
                    description
                    args {
                        name
                        description
                        type { kind name ofType { kind name ofType { kind name } } }
                        defaultValue
                    }
                    type { kind name ofType { kind name ofType { kind name } } }
                    isDeprecated
                    deprecationReason
                }
                inputFields {
                    name
                    description
                    type { kind name ofType { kind name ofType { kind name } } }
                    defaultValue
                }
                interfaces { kind name }
                enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
                possibleTypes { kind name }
            }
            directives { name description locations args { name description type { kind name ofType { kind name ofType { kind name } } } defaultValue } }
        }
    }
    """

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        url = arguments.get("url", "")
        headers = arguments.get("headers", {})
        timeout = arguments.get("timeout", 30)
        include_deprecated = arguments.get("include_deprecated", True)

        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument (GraphQL endpoint)."}

        try:
            # Ensure proper headers
            request_headers = {"Content-Type": "application/json", **headers}
            
            resp = requests.post(
                url,
                json={"query": self.INTROSPECTION_QUERY},
                headers=request_headers,
                timeout=timeout
            )

            if resp.status_code != 200:
                return {
                    "success": False,
                    "output": {},
                    "error": f"HTTP {resp.status_code}: {resp.text[:500]}"
                }

            data = resp.json()
            
            if "errors" in data:
                # Check if introspection is disabled
                error_msg = str(data["errors"])
                if "introspection" in error_msg.lower() or "schema" in error_msg.lower():
                    return {
                        "success": True,
                        "output": {
                            "url": url,
                            "introspection_enabled": False,
                            "errors": data["errors"]
                        },
                        "error": "Introspection disabled"
                    }
                return {"success": False, "output": {}, "error": f"GraphQL errors: {error_msg}"}

            schema = data.get("data", {}).get("__schema", {})
            types = schema.get("types", [])

            # Analyze schema for attack surface
            analysis = self._analyze_schema(types)

            return {
                "success": True,
                "output": {
                    "url": url,
                    "introspection_enabled": True,
                    "query_type": schema.get("queryType", {}).get("name"),
                    "mutation_type": schema.get("mutationType", {}).get("name"),
                    "subscription_type": schema.get("subscriptionType", {}).get("name"),
                    "directives_count": len(schema.get("directives", [])),
                    "types_count": len(types),
                    "analysis": analysis,
                    "raw_schema": schema if arguments.get("include_raw", False) else None
                },
                "error": ""
            }
        except requests.Timeout:
            return {"success": False, "output": {}, "error": f"Request timeout after {timeout}s"}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}

    def _analyze_schema(self, types: List[Dict]) -> Dict[str, Any]:
        """Analyze GraphQL schema for common vulnerability patterns."""
        mutations = []
        queries = []
        suspicious_fields = []
        input_types = []
        
        for t in types:
            if t.get("name", "").startswith("__"):
                continue
                
            if t.get("kind") == "OBJECT":
                fields = t.get("fields", [])
                for f in fields:
                    fname = f.get("name", "").lower()
                    # Look for suspicious field names
                    for pattern in ["debug", "system", "admin", "internal", "exec", "cmd", "shell", "run", "exec", "eval", "import", "upload", "file", "path", "read", "write", "delete", "execute"]:
                        if pattern in fname:
                            suspicious_fields.append({
                                "type": t.get("name"),
                                "field": f.get("name"),
                                "pattern": pattern,
                                "args": [a.get("name") for a in f.get("args", [])]
                            })
                
                # Check if this is a mutation type
                if any(f.get("name", "").lower() in ["create", "update", "delete", "insert", "upsert", "modify"] for f in fields):
                    mutations.append({"type": t.get("name"), "fields": [f.get("name") for f in fields]})
                    
            elif t.get("kind") == "INPUT_OBJECT":
                input_types.append({
                    "name": t.get("name"),
                    "fields": [f.get("name") for f in t.get("inputFields", [])]
                })

        # Find query/mutation root types
        query_type = next((t for t in types if t.get("name") == "Query"), None)
        mutation_type = next((t for t in types if t.get("name") == "Mutation"), None)

        if query_type:
            queries = [f.get("name") for f in query_type.get("fields", [])]
        if mutation_type:
            mutations = [f.get("name") for f in mutation_type.get("fields", [])]

        return {
            "queries": queries,
            "mutations": mutations,
            "input_types": input_types,
            "suspicious_fields": suspicious_fields,
            "total_types": len(types)
        }


TOOL_CLASS = GraphQLIntrospectionTool