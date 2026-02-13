"""Tree-sitter based parser for JavaScript/TypeScript codebases."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from tree_sitter import Query, QueryCursor
from tree_sitter_language_pack import get_language, get_parser

from logicgate.models import FunctionCall, FunctionDef, ImportInfo, RouteInfo

logger = logging.getLogger(__name__)

# HTTP methods recognised as Express route registrations
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "use", "all"})

# Directory that holds our .scm query files
_QUERIES_DIR = Path(__file__).resolve().parent / "queries"


class TreeSitterParser:
    """Parse JavaScript / TypeScript files using tree-sitter.

    Pre-compiles all ``.scm`` queries at init time so that repeated
    calls to ``find_*`` methods are fast.
    """

    def __init__(self) -> None:
        self._js_lang = get_language("javascript")
        self._ts_lang = get_language("typescript")
        self._js_parser = get_parser("javascript")
        self._ts_parser = get_parser("typescript")

        # Pre-compile queries for JS (used for TS too via separate lang)
        self._js_queries: dict[str, Query] = {}
        self._ts_queries: dict[str, Query] = {}
        self._load_queries()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_queries(self) -> None:
        """Read every .scm file in the queries directory and compile."""
        for scm_path in sorted(_QUERIES_DIR.glob("*.scm")):
            name = scm_path.stem  # e.g. "express_routes"
            text = scm_path.read_text()
            try:
                self._js_queries[name] = Query(self._js_lang, text)
                self._ts_queries[name] = Query(self._ts_lang, text)
            except Exception:
                logger.warning("Failed to compile query %s", scm_path, exc_info=True)

    def _lang_for(self, path: Path):
        """Return (language, parser, queries) tuple for a file path."""
        suffix = path.suffix.lower()
        if suffix in (".ts", ".tsx"):
            return self._ts_lang, self._ts_parser, self._ts_queries
        return self._js_lang, self._js_parser, self._js_queries

    def _run_query(self, query_name: str, path: Path, source: bytes, tree):
        """Run a named pre-compiled query and return the match list."""
        _, _, queries = self._lang_for(path)
        q = queries.get(query_name)
        if q is None:
            logger.warning("Query %r not found", query_name)
            return []
        cursor = QueryCursor(q)
        return cursor.matches(tree.root_node)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_file(self, path: Path):
        """Parse a file and return (tree, source_bytes)."""
        source = path.read_bytes()
        _, parser, _ = self._lang_for(path)
        tree = parser.parse(source)
        return tree, source

    def find_routes(self, path: Path) -> list[RouteInfo]:
        """Find Express route definitions in *path*."""
        try:
            tree, source = self.parse_file(path)
        except Exception:
            logger.warning("Could not parse %s", path, exc_info=True)
            return []

        matches = self._run_query("express_routes", path, source, tree)
        results: list[RouteInfo] = []

        for _pattern_idx, captures in matches:
            method_nodes = captures.get("method", [])
            obj_nodes = captures.get("obj", [])
            args_nodes = captures.get("args", [])
            call_nodes = captures.get("call", [])

            if not (method_nodes and obj_nodes and args_nodes):
                continue

            method_text = method_nodes[0].text.decode()
            if method_text not in _HTTP_METHODS:
                continue

            args_node = args_nodes[0]
            call_node = call_nodes[0] if call_nodes else args_node

            # Collect the named children of arguments (skip parens, commas)
            arg_children = [c for c in args_node.named_children]

            if not arg_children:
                continue

            # Determine route_pattern and handler
            route_pattern: Optional[str] = None
            handler_node = None
            middleware: list[str] = []

            # For app.use(...) the first arg may be a string path or directly a handler
            first_arg = arg_children[0]

            if first_arg.type == "string":
                # Extract the string content (strip quotes)
                route_pattern = self._extract_string(first_arg)
                remaining = arg_children[1:]
            else:
                # No string path; for use() this is a direct handler
                route_pattern = "*"
                remaining = arg_children

            # The last remaining arg is the handler; middle ones are middleware
            if remaining:
                handler_node = remaining[-1]
                for mid in remaining[:-1]:
                    if mid.type == "identifier":
                        middleware.append(mid.text.decode())
                    elif mid.type == "member_expression":
                        middleware.append(mid.text.decode())

            # If this looks like middleware setup (e.g., app.use(express.json()))
            # without any function handler, we should still record it but the
            # handler is the call expression itself.
            if handler_node is None:
                continue

            # Determine handler line range
            handler_start_line = handler_node.start_point[0] + 1
            handler_end_line = handler_node.end_point[0] + 1
            handler_source = handler_node.text.decode()

            # For use() without explicit path, check if the handler is
            # actually a function-like node; if it's just a call like
            # express.json(), skip it (not a route handler)
            if method_text == "use":
                if handler_node.type not in (
                    "arrow_function",
                    "function_expression",
                    "function",
                ):
                    # e.g. app.use(express.json()) - not a route handler
                    continue

            results.append(
                RouteInfo(
                    file_path=str(path),
                    http_method=method_text.upper(),
                    route_pattern=route_pattern if route_pattern else "*",
                    handler_start_line=handler_start_line,
                    handler_end_line=handler_end_line,
                    handler_source=handler_source,
                    middleware=middleware,
                )
            )

        return results

    def find_imports(self, path: Path) -> list[ImportInfo]:
        """Find CommonJS require() imports in *path*."""
        try:
            tree, source = self.parse_file(path)
        except Exception:
            logger.warning("Could not parse %s", path, exc_info=True)
            return []

        matches = self._run_query("require_imports", path, source, tree)
        results: list[ImportInfo] = []

        for _pattern_idx, captures in matches:
            name_nodes = captures.get("name", [])
            req_fn_nodes = captures.get("req_fn", [])
            source_nodes = captures.get("source", [])
            decl_nodes = captures.get("decl", [])

            if not (name_nodes and req_fn_nodes and source_nodes):
                continue

            # Only match require() calls, not arbitrary functions
            if req_fn_nodes[0].text.decode() != "require":
                continue

            var_name = name_nodes[0].text.decode()
            import_path = self._extract_string(source_nodes[0])
            line = decl_nodes[0].start_point[0] + 1 if decl_nodes else name_nodes[0].start_point[0] + 1

            results.append(
                ImportInfo(
                    name=var_name,
                    path=import_path,
                    file_path=str(path),
                    line=line,
                )
            )

        return results

    def find_function_defs(self, path: Path) -> list[FunctionDef]:
        """Find named function definitions in *path*."""
        try:
            tree, source = self.parse_file(path)
        except Exception:
            logger.warning("Could not parse %s", path, exc_info=True)
            return []

        matches = self._run_query("function_defs", path, source, tree)
        results: list[FunctionDef] = []

        for pattern_idx, captures in matches:
            name_nodes = captures.get("name", [])
            # Pattern 0 = function_declaration, pattern 1 = arrow function
            func_nodes = captures.get("func", [])
            arrow_nodes = captures.get("arrow", [])
            decl_nodes = captures.get("decl", [])

            if not name_nodes:
                continue

            fn_name = name_nodes[0].text.decode()

            # Determine the node that spans the whole function
            if func_nodes:
                span_node = func_nodes[0]
            elif decl_nodes:
                span_node = decl_nodes[0]
            else:
                continue

            results.append(
                FunctionDef(
                    name=fn_name,
                    file_path=str(path),
                    start_line=span_node.start_point[0] + 1,
                    end_line=span_node.end_point[0] + 1,
                    source=span_node.text.decode(),
                )
            )

        return results

    def find_function_calls(self, path: Path) -> list[FunctionCall]:
        """Find function call sites in *path*."""
        try:
            tree, source = self.parse_file(path)
        except Exception:
            logger.warning("Could not parse %s", path, exc_info=True)
            return []

        matches = self._run_query("function_calls", path, source, tree)
        results: list[FunctionCall] = []

        for pattern_idx, captures in matches:
            # Pattern 0: direct call  (fn_name, call)
            # Pattern 1: member call  (obj, method_name, member_call)
            fn_name_nodes = captures.get("fn_name", [])
            obj_nodes = captures.get("obj", [])
            method_name_nodes = captures.get("method_name", [])

            if fn_name_nodes:
                # Direct call
                node = fn_name_nodes[0]
                results.append(
                    FunctionCall(
                        name=node.text.decode(),
                        file_path=str(path),
                        line=node.start_point[0] + 1,
                        object_name=None,
                    )
                )
            elif method_name_nodes and obj_nodes:
                # Member call
                method_node = method_name_nodes[0]
                obj_node = obj_nodes[0]
                # For the object, get just the identifier text
                obj_text = obj_node.text.decode()
                results.append(
                    FunctionCall(
                        name=method_node.text.decode(),
                        file_path=str(path),
                        line=method_node.start_point[0] + 1,
                        object_name=obj_text,
                    )
                )

        return results

    @staticmethod
    def _extract_string(string_node) -> str:
        """Extract the text content of a tree-sitter string node (strip quotes)."""
        # A string node's text includes quotes: 'foo' or "foo"
        raw = string_node.text.decode()
        # Strip outer quotes
        if len(raw) >= 2 and raw[0] in ("'", '"', '`'):
            return raw[1:-1]
        return raw
