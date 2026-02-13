"""Dependency graph builder for JavaScript/TypeScript codebases."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import networkx as nx

from logicgate.models import FunctionCall, FunctionDef, ImportInfo, RouteInfo
from logicgate.parser import TreeSitterParser

logger = logging.getLogger(__name__)

_SKIP_DIRS = frozenset({"node_modules", ".git", "dist", "build", ".next", "__pycache__"})
_JS_EXTENSIONS = frozenset({".js", ".ts", ".jsx", ".tsx"})


class DependencyGraph:
    """Build and query a directed dependency graph over JS/TS functions.

    Nodes are individual function definitions keyed by ``"filepath:funcname"``.
    Edges represent "caller -> callee" relationships resolved via naive
    same-file matching and simple relative-import resolution.
    """

    def __init__(self, parser: TreeSitterParser) -> None:
        self.parser = parser
        self.graph: nx.DiGraph = nx.DiGraph()
        self._file_functions: dict[str, list[FunctionDef]] = {}
        self._file_calls: dict[str, list[FunctionCall]] = {}
        self._file_imports: dict[str, list[ImportInfo]] = {}
        self._symbol_table: dict[str, FunctionDef] = {}

    @property
    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_graph(self, directory: Path) -> None:
        """Walk *directory* for .js/.ts files and build the dependency graph."""
        for source_path in self._walk_sources(directory):
            str_path = str(source_path)

            defs = self.parser.find_function_defs(source_path)
            calls = self.parser.find_function_calls(source_path)
            imports = self.parser.find_imports(source_path)

            self._file_functions[str_path] = defs
            self._file_calls[str_path] = calls
            self._file_imports[str_path] = imports

            for fdef in defs:
                node_id = f"{str_path}:{fdef.name}"
                self._symbol_table[node_id] = fdef
                self.graph.add_node(node_id, data=fdef)

        # Phase 2: resolve calls -> edges
        for file_path, calls in self._file_calls.items():
            self._resolve_calls(file_path, calls)

    def get_slice(self, node_id: str, depth: int = 5) -> list[FunctionDef]:
        """Return all FunctionDef objects reachable from *node_id* via BFS."""
        if node_id not in self.graph:
            return []

        reachable: set[str] = {node_id}
        for _u, v in nx.bfs_edges(self.graph, node_id, depth_limit=depth):
            reachable.add(v)

        result: list[FunctionDef] = []
        for nid in reachable:
            data = self.graph.nodes[nid].get("data")
            if data is not None:
                result.append(data)
        return result

    def get_route_context(self, route: RouteInfo, depth: int = 5) -> str:
        """Build a source-code context string for *route*.

        Finds which functions the route handler calls (by checking
        call-sites whose line numbers fall within the handler's range),
        resolves each to its graph node, and collects a BFS slice of all
        reachable functions.
        """
        file_path = route.file_path
        handler_start = route.handler_start_line
        handler_end = route.handler_end_line

        # Gather call-site names that appear inside the handler
        calls_in_handler: list[FunctionCall] = []
        for call in self._file_calls.get(file_path, []):
            if handler_start <= call.line <= handler_end:
                calls_in_handler.append(call)

        # Resolve each call to a symbol-table entry and collect slices
        seen_node_ids: set[str] = set()
        all_defs: list[FunctionDef] = []

        for call in calls_in_handler:
            # Try same-file resolution first
            candidate_id = f"{file_path}:{call.name}"
            if candidate_id in self._symbol_table:
                if candidate_id not in seen_node_ids:
                    for fdef in self.get_slice(candidate_id, depth=depth):
                        nid = f"{fdef.file_path}:{fdef.name}"
                        if nid not in seen_node_ids:
                            seen_node_ids.add(nid)
                            all_defs.append(fdef)
                continue

            # Try imported-file resolution
            resolved = self._resolve_call_via_imports(file_path, call.name)
            if resolved and resolved not in seen_node_ids:
                for fdef in self.get_slice(resolved, depth=depth):
                    nid = f"{fdef.file_path}:{fdef.name}"
                    if nid not in seen_node_ids:
                        seen_node_ids.add(nid)
                        all_defs.append(fdef)

        if not all_defs:
            return (
                f"// File: {route.file_path}, "
                f"Lines {handler_start}-{handler_end}\n"
                f"{route.handler_source}\n"
            )

        parts: list[str] = []
        for fdef in all_defs:
            parts.append(
                f"// File: {fdef.file_path}, "
                f"Lines {fdef.start_line}-{fdef.end_line}\n"
                f"{fdef.source}"
            )
        return "\n\n".join(parts) + "\n"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _walk_sources(self, directory: Path):
        """Yield all .js/.ts file paths under *directory*, skipping noise."""
        for child in sorted(directory.rglob("*")):
            if child.is_file() and child.suffix in _JS_EXTENSIONS:
                if not any(part in _SKIP_DIRS for part in child.parts):
                    yield child

    def _resolve_calls(self, file_path: str, calls: list[FunctionCall]) -> None:
        """Add graph edges for every call in *file_path* that resolves."""
        local_defs = {d.name: d for d in self._file_functions.get(file_path, [])}

        for call in calls:
            caller_name = self._find_enclosing_function(file_path, call.line)
            if not caller_name:
                continue

            caller_id = f"{file_path}:{caller_name}"

            # 1) Same-file resolution
            if call.name in local_defs:
                callee_id = f"{file_path}:{call.name}"
                if caller_id in self.graph and callee_id in self.graph:
                    self.graph.add_edge(caller_id, callee_id)
                continue

            # 2) Import-based resolution
            resolved = self._resolve_call_via_imports(file_path, call.name)
            if resolved and caller_id in self.graph:
                self.graph.add_edge(caller_id, resolved)

    def _find_enclosing_function(self, file_path: str, line: int) -> Optional[str]:
        """Return the name of the function that encloses *line*, or None."""
        best: Optional[FunctionDef] = None
        for fdef in self._file_functions.get(file_path, []):
            if fdef.start_line <= line <= fdef.end_line:
                if best is None or (fdef.end_line - fdef.start_line) < (best.end_line - best.start_line):
                    best = fdef
        return best.name if best else None

    def _resolve_call_via_imports(self, file_path: str, call_name: str) -> Optional[str]:
        """Try to resolve *call_name* via imports in *file_path*."""
        for imp in self._file_imports.get(file_path, []):
            if imp.name == call_name:
                resolved_path = self._resolve_import_path(Path(file_path), imp.path)
                if resolved_path is not None:
                    candidate_id = f"{str(resolved_path)}:{call_name}"
                    if candidate_id in self._symbol_table:
                        return candidate_id
        return None

    def _resolve_import_path(self, current_file: Path, import_path: str) -> Optional[Path]:
        """Resolve a relative import path to an actual file."""
        if not import_path.startswith("."):
            return None

        base_dir = current_file.parent
        candidate = (base_dir / import_path).resolve()

        probes = [
            candidate,
            candidate.with_suffix(".js"),
            candidate.with_suffix(".ts"),
            candidate / "index.js",
            candidate / "index.ts",
        ]

        for probe in probes:
            if probe.is_file():
                return probe

        return None
