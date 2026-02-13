"""Tests for the DependencyGraph module."""

from pathlib import Path

import pytest

from logicgate.graph import DependencyGraph
from logicgate.parser import TreeSitterParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def graph():
    parser = TreeSitterParser()
    g = DependencyGraph(parser)
    g.build_graph(FIXTURES_DIR)
    return g


@pytest.fixture(scope="module")
def parser():
    return TreeSitterParser()


class TestBuildGraph:
    def test_nodes_created(self, graph):
        assert graph.node_count == 3

    def test_node_names(self, graph):
        node_ids = list(graph.graph.nodes)
        names = [nid.split(":")[-1] for nid in node_ids]
        assert set(names) == {"initDataFile", "readBookings", "writeBookings"}


class TestGetSlice:
    def test_slice_returns_self(self, graph):
        # readBookings doesn't call other named functions, so slice = just itself
        for nid in graph.graph.nodes:
            if nid.endswith(":readBookings"):
                result = graph.get_slice(nid)
                assert len(result) >= 1
                names = {d.name for d in result}
                assert "readBookings" in names

    def test_slice_unknown_node(self, graph):
        result = graph.get_slice("nonexistent:func")
        assert result == []


class TestGetRouteContext:
    def test_context_for_get_bookings(self, graph, parser):
        routes = parser.find_routes(FIXTURES_DIR / "server.js")
        get_bookings = [r for r in routes if r.route_pattern == "/api/bookings" and r.http_method == "GET"]
        assert len(get_bookings) == 1

        context = graph.get_route_context(get_bookings[0])
        assert "readBookings" in context

    def test_context_for_post_bookings(self, graph, parser):
        routes = parser.find_routes(FIXTURES_DIR / "server.js")
        post_bookings = [r for r in routes if r.route_pattern == "/api/bookings" and r.http_method == "POST"]
        assert len(post_bookings) == 1

        context = graph.get_route_context(post_bookings[0])
        assert "readBookings" in context
        assert "writeBookings" in context

    def test_context_fallback_for_static_route(self, graph, parser):
        routes = parser.find_routes(FIXTURES_DIR / "server.js")
        get_root = [r for r in routes if r.route_pattern == "/" and r.http_method == "GET"]
        assert len(get_root) == 1

        # GET / doesn't call any named functions, so fallback to handler source
        context = graph.get_route_context(get_root[0])
        assert "sendFile" in context or "res" in context
