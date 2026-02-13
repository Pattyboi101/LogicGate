"""Tests for the TreeSitterParser module."""

from pathlib import Path

import pytest

from logicgate.parser import TreeSitterParser

FIXTURE = Path(__file__).parent / "fixtures" / "server.js"


@pytest.fixture(scope="module")
def parser():
    return TreeSitterParser()


class TestFindRoutes:
    def test_route_count(self, parser):
        routes = parser.find_routes(FIXTURE)
        # 7 HTTP routes + 2 USE middleware
        assert len(routes) == 9

    def test_http_routes(self, parser):
        routes = parser.find_routes(FIXTURE)
        route_tuples = [(r.http_method, r.route_pattern) for r in routes]
        assert ("GET", "/api/bookings") in route_tuples
        assert ("POST", "/api/bookings") in route_tuples
        assert ("GET", "/api/bookings/:id") in route_tuples
        assert ("PATCH", "/api/bookings/:id") in route_tuples
        assert ("DELETE", "/api/bookings/:id") in route_tuples
        assert ("GET", "/") in route_tuples
        assert ("GET", "/admin") in route_tuples

    def test_middleware_routes(self, parser):
        routes = parser.find_routes(FIXTURE)
        use_routes = [r for r in routes if r.http_method == "USE"]
        assert len(use_routes) == 2

    def test_handler_source_not_empty(self, parser):
        routes = parser.find_routes(FIXTURE)
        for r in routes:
            assert r.handler_source, f"Empty handler for {r.http_method} {r.route_pattern}"

    def test_line_numbers_valid(self, parser):
        routes = parser.find_routes(FIXTURE)
        for r in routes:
            assert r.handler_start_line > 0
            assert r.handler_end_line >= r.handler_start_line


class TestFindImports:
    def test_import_count(self, parser):
        imports = parser.find_imports(FIXTURE)
        assert len(imports) == 3

    def test_import_names(self, parser):
        imports = parser.find_imports(FIXTURE)
        names = {i.name for i in imports}
        assert names == {"express", "fs", "path"}

    def test_import_paths(self, parser):
        imports = parser.find_imports(FIXTURE)
        paths = {i.path for i in imports}
        assert paths == {"express", "fs", "path"}


class TestFindFunctionDefs:
    def test_function_count(self, parser):
        funcs = parser.find_function_defs(FIXTURE)
        assert len(funcs) == 3

    def test_function_names(self, parser):
        funcs = parser.find_function_defs(FIXTURE)
        names = {f.name for f in funcs}
        assert names == {"initDataFile", "readBookings", "writeBookings"}

    def test_source_not_empty(self, parser):
        funcs = parser.find_function_defs(FIXTURE)
        for f in funcs:
            assert f.source, f"Empty source for {f.name}"


class TestFindFunctionCalls:
    def test_calls_found(self, parser):
        calls = parser.find_function_calls(FIXTURE)
        assert len(calls) > 0

    def test_key_direct_calls(self, parser):
        calls = parser.find_function_calls(FIXTURE)
        direct_names = {c.name for c in calls if c.object_name is None}
        assert "readBookings" in direct_names
        assert "writeBookings" in direct_names
        assert "initDataFile" in direct_names
        assert "require" in direct_names

    def test_method_calls(self, parser):
        calls = parser.find_function_calls(FIXTURE)
        method_calls = {(c.object_name, c.name) for c in calls if c.object_name}
        assert ("res", "json") in method_calls
        assert ("app", "get") in method_calls or ("app", "post") in method_calls
