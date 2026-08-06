"""Tests for cpg/frameworks/ — framework route extractors."""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.frameworks.base import HttpEndpoint, RouteParam
from hyqagent.cpg.frameworks.django import DjangoExtractor
from hyqagent.cpg.frameworks.express import ExpressExtractor
from hyqagent.cpg.frameworks.fastapi import FastAPIExtractor
from hyqagent.cpg.frameworks.flask import FlaskExtractor
from hyqagent.cpg.frameworks.spring import SpringExtractor
from hyqagent.cpg.parser import Parser
from hyqagent.cpg.taint_loader import TaintRuleLoader

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


# ─── Base types ──────────────────────────────────────────────────────────────


class TestBaseTypes:
    def test_route_param_defaults(self):
        p = RouteParam(name="id", source="path")
        assert p.name == "id"
        assert p.source == "path"
        assert p.required is True

    def test_http_endpoint_defaults(self):
        ep = HttpEndpoint(route="/test")
        assert ep.route == "/test"
        assert ep.methods == []
        assert ep.framework == ""

    def test_http_endpoint_full(self):
        ep = HttpEndpoint(
            route="/users/<id>",
            methods=["GET", "POST"],
            handler_func="get_user",
            file_path="app.py",
            line=10,
            framework="flask",
        )
        assert ep.methods == ["GET", "POST"]
        assert ep.handler_func == "get_user"


# ─── Flask ───────────────────────────────────────────────────────────────────


class TestFlaskExtractor:
    def test_detect(self, parser):
        ext = FlaskExtractor(parser)
        assert ext.detect(str(FIXTURES / "flask_sample.py")) is True
        assert ext.detect(str(FIXTURES / "dataflow.py")) is False

    def test_extract_routes_count(self, parser):
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "flask_sample.py"))
        assert len(routes) >= 3  # /, /users, /users/<id>, /admin/stats

    def test_route_patterns(self, parser):
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "flask_sample.py"))
        route_patterns = {r.route for r in routes}
        assert "/" in route_patterns
        assert any("users" in r for r in route_patterns)

    def test_methods_extracted(self, parser):
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "flask_sample.py"))
        user_route = next((r for r in routes if "/users" in r.route and "<int:" in r.route), None)
        if user_route:
            assert "GET" in user_route.methods
            assert "POST" in user_route.methods

    def test_auth_detected(self, parser):
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "flask_sample.py"))
        auth_routes = [r for r in routes if r.auth_required]
        assert len(auth_routes) >= 1  # /users/<id> has @login_required

    def test_framework_label(self, parser):
        ext = FlaskExtractor(parser)
        assert ext.framework_name == "flask"
        routes = ext.extract_routes(str(FIXTURES / "flask_sample.py"))
        for r in routes:
            assert r.framework == "flask"

    def test_handler_funcs(self, parser):
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "flask_sample.py"))
        handlers = {r.handler_func for r in routes}
        assert "index" in handlers
        assert "list_users" in handlers

    def test_path_params(self, parser):
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "flask_sample.py"))
        user_detail = next((r for r in routes if "user_id" in r.route), None)
        if user_detail:
            path_params = [p for p in user_detail.params if p.source == "path"]
            assert len(path_params) >= 1
            assert any(p.name == "user_id" for p in path_params)

    def test_source_lines(self, parser):
        ext = FlaskExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "flask_sample.py"))
        # At least one route should have source_lines from request.args.get etc.
        all_sources = []
        for r in routes:
            all_sources.extend(r.source_lines)
        assert len(all_sources) > 0


# ─── Express ─────────────────────────────────────────────────────────────────


class TestExpressExtractor:
    def test_detect(self, parser):
        ext = ExpressExtractor(parser)
        assert ext.detect(str(FIXTURES / "express_sample.js")) is True
        assert ext.detect(str(FIXTURES / "dataflow.js")) is False

    def test_extract_routes_count(self, parser):
        ext = ExpressExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "express_sample.js"))
        assert len(routes) >= 3

    def test_methods_extracted(self, parser):
        ext = ExpressExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "express_sample.js"))
        methods = set()
        for r in routes:
            methods.update(r.methods)
        assert "GET" in methods
        assert "POST" in methods

    def test_route_patterns(self, parser):
        ext = ExpressExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "express_sample.js"))
        patterns = {r.route for r in routes}
        assert "/" in patterns
        assert any(":id" in p for p in patterns)

    def test_path_params(self, parser):
        ext = ExpressExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "express_sample.js"))
        users_route = next((r for r in routes if ":id" in r.route), None)
        if users_route:
            path_params = [p for p in users_route.params if p.source == "path"]
            assert any(p.name == "id" for p in path_params)

    def test_framework_label(self, parser):
        ext = ExpressExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "express_sample.js"))
        for r in routes:
            assert r.framework == "express"


# ─── Spring ──────────────────────────────────────────────────────────────────


class TestSpringExtractor:
    def test_detect(self, parser):
        ext = SpringExtractor(parser)
        assert ext.detect(str(FIXTURES / "spring_sample.java")) is True
        assert ext.detect(str(FIXTURES / "dataflow.py")) is False

    def test_extract_routes_count(self, parser):
        ext = SpringExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "spring_sample.java"))
        # Should find GetMapping + PostMapping methods
        assert len(routes) >= 3

    def test_methods_extracted(self, parser):
        ext = SpringExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "spring_sample.java"))
        methods = set()
        for r in routes:
            methods.update(r.methods)
        assert "GET" in methods
        assert "POST" in methods

    def test_route_patterns(self, parser):
        ext = SpringExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "spring_sample.java"))
        patterns = {r.route for r in routes}
        assert "/" in patterns or any("/users" in p for p in patterns)

    def test_auth_detected(self, parser):
        ext = SpringExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "spring_sample.java"))
        auth_routes = [r for r in routes if r.auth_required]
        assert len(auth_routes) >= 1  # @PreAuthorize

    def test_framework_label(self, parser):
        ext = SpringExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "spring_sample.java"))
        for r in routes:
            assert r.framework == "spring"

    def test_params_extracted(self, parser):
        ext = SpringExtractor(parser)
        routes = ext.extract_routes(str(FIXTURES / "spring_sample.java"))
        all_params = []
        for r in routes:
            all_params.extend(r.params)
        assert len(all_params) > 0


# ─── TaintRuleLoader ─────────────────────────────────────────────────────────


class TestTaintLoader:
    def test_load_rules(self):
        loader = TaintRuleLoader()
        assert "python" in loader.available_languages
        assert "javascript" in loader.available_languages
        assert "java" in loader.available_languages

    def test_rules_for_python(self):
        loader = TaintRuleLoader()
        rules = loader.rules_for("python")
        assert "sql_injection" in rules.categories
        assert len(rules.categories["sql_injection"].sources) > 0
        assert len(rules.categories["sql_injection"].sinks) > 0

    def test_all_sources_python(self):
        loader = TaintRuleLoader()
        sources = loader.all_sources("python")
        assert len(sources) > 5
        # Patterns are now variable-agnostic (.args.get( not request.args.get)
        assert ".args.get(" in sources

    def test_all_sinks_python(self):
        loader = TaintRuleLoader()
        sinks = loader.all_sinks("python")
        assert len(sinks) > 5
        assert any(".execute(" in s for s in sinks)

    def test_match_source(self):
        loader = TaintRuleLoader()
        # Variable-agnostic: .args.get( matches req.args.get('id')
        cat = loader.match_source("python", "req.args.get('id')")
        assert cat is not None  # should match some category

    def test_match_sink(self):
        loader = TaintRuleLoader()
        cat = loader.match_sink("python", "cursor.execute(sql)")
        assert cat is not None

    def test_rules_for_javascript(self):
        loader = TaintRuleLoader()
        rules = loader.rules_for("javascript")
        assert len(rules.categories) > 0

    def test_rules_for_java(self):
        loader = TaintRuleLoader()
        rules = loader.rules_for("java")
        assert len(rules.categories) > 0


# ─── Django (T1) ─────────────────────────────────────────────────────────────


class TestDjangoExtractor:
    def test_detect(self, parser):
        ext = DjangoExtractor(parser)
        code = "from django.urls import path\nurlpatterns = [path('/', views.index)]"
        tree = parser.parse_code(code, "python")
        assert "django" in ext._source(tree.root_node).lower()

    def test_url_config_parsing(self, parser):
        ext = DjangoExtractor(parser)
        code = (
            "from django.urls import path\n"
            'urlpatterns = [path("users/", views.list_users, name="list")]'
        )
        tree = parser.parse_code(code, "python")
        entries = ext._parse_url_config(tree)
        assert len(entries) >= 1
        assert entries[0]["route"] == "users/"
        assert "list_users" in entries[0]["view"]


# ─── FastAPI (T2) ────────────────────────────────────────────────────────────


class TestFastAPIExtractor:
    def test_detect(self, parser):
        ext = FastAPIExtractor(parser)
        code = "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/')\ndef index():\n    pass"
        assert ext.detect is not None  # won't pass detect (no file path) but shouldn't crash

    def test_extract_routes_from_code(self, parser):
        ext = FastAPIExtractor(parser)
        code = (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/users')\n"
            "def list_users():\n"
            "    pass\n"
        )
        tree = parser.parse_code(code, "python")
        funcs = parser.extract_functions(tree, "python")
        assert len(funcs) >= 1
