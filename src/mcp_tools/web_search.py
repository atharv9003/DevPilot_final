"""
Web Search API Tool (MCP Tool 3)
Connects to Tavily API for technical documentation and error lookups,
with offline synthetic documentation lookup when API key is unavailable or offline.
"""
import os
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
from config.settings import settings, is_online


class WebSearchTool:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.tavily_api_key

    def search(self, query: str, max_results: int = 3) -> List[Dict[str, str]]:
        # If API key is provided and online, execute Tavily Search over HTTPS
        if self.api_key and self.api_key.strip() and is_online("api.tavily.com", 443, timeout=0.5):
            try:
                url = "https://api.tavily.com/search"
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "DevPilot/1.0"
                }
                payload = json.dumps({
                    "api_key": self.api_key,
                    "query": query,
                    "search_depth": "basic",
                    "include_answer": True,
                    "max_results": max_results
                }).encode("utf-8")

                req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=3) as response:
                    data = json.loads(response.read().decode("utf-8"))
                    results = []
                    if "results" in data:
                        for r in data["results"][:max_results]:
                            results.append({
                                "title": r.get("title", ""),
                                "url": r.get("url", ""),
                                "snippet": r.get("content", "")
                            })
                    if results:
                        return results
            except Exception:
                pass

        # Offline Technical Knowledge Base (Zero-Key fallback)
        return self._offline_search(query, max_results)

    def _offline_search(self, query: str, max_results: int) -> List[Dict[str, str]]:
        q_lower = query.lower()
        kb = [
            {
                "keywords": ["indexerror", "list index out of range", "off by one", "binary search"],
                "title": "Python IndexError: list index out of range - Python Docs",
                "url": "https://docs.python.org/3/tutorial/errors.html#indexerror",
                "snippet": "IndexError occurs when attempting to access an index outside the boundaries of a sequence (e.g. index >= len(seq)). In algorithms like binary search, check high boundary conditions `high = len(arr) - 1` vs `high = len(arr)`."
            },
            {
                "keywords": ["attributeerror", "nonetype", "object has no attribute"],
                "title": "Handling AttributeError: 'NoneType' object has no attribute",
                "url": "https://docs.python.org/3/library/exceptions.html#AttributeError",
                "snippet": "Occurs when an operation or attribute lookup is attempted on None. Ensure functions explicitly return valid objects or guard with `if obj is not None:` before accessing attributes."
            },
            {
                "keywords": ["keyerror", "dictionary", "dict get"],
                "title": "Python KeyError and Safe Dictionary Access",
                "url": "https://docs.python.org/3/library/stdtypes.html#dict.get",
                "snippet": "A KeyError is raised when a mapping key is not found in the dictionary. Use `dict.get(key, default)` or verify presence with `if key in dict:` to prevent unhandled exceptions."
            },
            {
                "keywords": ["circular import", "importerror", "cannot import name"],
                "title": "Resolving Circular Import Dependencies in Python",
                "url": "https://docs.python.org/3/reference/import.html",
                "snippet": "Circular imports occur when module A imports B which imports A. Refactor shared dependencies into a separate module (e.g., types.py or common.py) or use deferred imports inside function bodies."
            },
            {
                "keywords": ["zerodivisionerror", "division by zero"],
                "title": "Handling ZeroDivisionError in Python Numerics",
                "url": "https://docs.python.org/3/library/exceptions.html#ZeroDivisionError",
                "snippet": "Raised when second argument for division or modulo is zero. Validate divisor before division or handle with a try-except block returning a default value or NaN."
            }
        ]

        matched = []
        for entry in kb:
            if any(k in q_lower for k in entry["keywords"]):
                matched.append({
                    "title": entry["title"],
                    "url": entry["url"],
                    "snippet": entry["snippet"]
                })

        if not matched:
            matched.append({
                "title": "Python Standard Library Debugging Guide",
                "url": "https://docs.python.org/3/library/debug.html",
                "snippet": f"Generic technical documentation match for query: {query}. Verify syntax, data types, and scope boundaries."
            })

        return matched[:max_results]
