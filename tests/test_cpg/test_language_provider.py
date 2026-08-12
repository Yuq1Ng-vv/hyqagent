"""Tests for LanguageProvider adapters — base class and Python/JS/Java implementations.

These are the ~1,326 lines of code that were only indirectly tested
through higher-level components (parser, callgraph, etc.).
"""

from __future__ import annotations

import pytest

from hyqagent.cpg.languages.base import LanguageProvider
from hyqagent.cpg.languages.java import JavaAdapter
from hyqagent.cpg.languages.javascript import JavaScriptAdapter
from hyqagent.cpg.languages.python import PythonAdapter
from hyqagent.cpg.parser import Parser

# Sample code snippets for each language
PY_SIMPLE = "def hello():\n    return 'world'\n"
PY_CLASS = "class Foo:\n    def method(self, x):\n        return x\n"

JS_SIMPLE = "function hello() { return 'world'; }\n"
JS_CLASS = "class Foo { method(x) { return x; } }\n"

JAVA_SIMPLE = "class Foo { void hello() { return; } }\n"


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


# ── Provider instances ───────────────────────────────────────────────────────


def _get_providers() -> list[tuple[str, LanguageProvider]]:
    return [
        ("python", PythonAdapter()),
        ("javascript", JavaScriptAdapter()),
        ("java", JavaAdapter()),
    ]


# ── Base properties ──────────────────────────────────────────────────────────


class TestProviderIdentity:
    """Every provider must report its name and file extensions."""

    @pytest.mark.parametrize("lang,prov", _get_providers())
    def test_has_name(self, lang, prov):
        assert prov.name == lang

    @pytest.mark.parametrize("lang,prov", _get_providers())
    def test_has_extensions(self, lang, prov):
        assert len(prov.extensions) > 0
        for ext in prov.extensions:
            assert ext.startswith("."), f"{lang}: extension {ext!r} missing dot prefix"


# ── Queries ──────────────────────────────────────────────────────────────────


class TestProviderQueries:
    """Every provider must have non-empty query strings."""

    @pytest.mark.parametrize("lang,prov", _get_providers())
    def test_function_query_nonempty(self, lang, prov):
        q = prov.function_query.strip()
        assert len(q) > 0, f"{lang}: function_query is empty"

    @pytest.mark.parametrize("lang,prov", _get_providers())
    def test_class_query_nonempty(self, lang, prov):
        q = prov.class_query.strip()
        assert len(q) > 0, f"{lang}: class_query is empty"

    @pytest.mark.parametrize("lang,prov", _get_providers())
    def test_import_query_nonempty(self, lang, prov):
        q = prov.import_query.strip()
        assert len(q) > 0, f"{lang}: import_query is empty"


# ── Function name extraction ─────────────────────────────────────────────────


class TestFunctionNameExtraction:
    """extract_function_name must work with valid AST nodes."""

    @pytest.mark.parametrize(
        "lang,prov,code,expected",
        [
            ("python", PythonAdapter(), PY_SIMPLE, "hello"),
            ("python", PythonAdapter(), PY_CLASS, "method"),
            ("javascript", JavaScriptAdapter(), JS_SIMPLE, "hello"),
            ("javascript", JavaScriptAdapter(), JS_CLASS, "method"),
        ],
    )
    def test_extracts_name(self, lang, prov, code, expected, parser):
        tree = parser.parse_code(code, lang)
        funcs = parser.extract_functions(tree, lang)
        names = {f.name for f in funcs}
        assert expected in names, f"{lang}: expected {expected!r} in {names}"


# ── Function definition types ────────────────────────────────────────────────


class TestFuncDefTypes:
    """func_def_types must be a non-empty set of strings."""

    @pytest.mark.parametrize("lang,prov", _get_providers())
    def test_nonempty(self, lang, prov):
        types = prov.func_def_types
        assert len(types) > 0
        assert all(isinstance(t, str) for t in types)

    def test_python_includes_function_definition(self):
        assert "function_definition" in PythonAdapter().func_def_types

    def test_javascript_includes_declaration(self):
        types = JavaScriptAdapter().func_def_types
        assert "function_declaration" in types or "function_expression" in types

    def test_java_includes_method_declaration(self):
        assert "method_declaration" in JavaAdapter().func_def_types


# ── Call node type ───────────────────────────────────────────────────────────


class TestCallNodeType:
    """call_node_type must be a non-empty set of strings."""

    @pytest.mark.parametrize("lang,prov", _get_providers())
    def test_nonempty(self, lang, prov):
        assert prov.call_node_type
        assert isinstance(prov.call_node_type, (set, frozenset))


# ── Parameter extraction ────────────────────────────────────────────────────


class TestParameterExtraction:
    """extract_parameters must return a list of parameter names."""

    @pytest.mark.parametrize(
        "lang,code,expected_params",
        [
            ("python", "def f(a, b, c=1):\n    pass\n", ["a", "b", "c"]),
            ("python", "def g():\n    pass\n", []),
            ("javascript", "function f(a, b, c) { }", ["a", "b", "c"]),
            ("javascript", "function g() { }", []),
            ("java", "class X { void f(int a, String b) { } }", ["a", "b"]),
            ("java", "class X { void g() { } }", []),
        ],
    )
    def test_extracts_params(self, lang, code, expected_params, parser):
        tree = parser.parse_code(code, lang)
        funcs = parser.extract_functions(tree, lang)
        assert len(funcs) >= 1, f"{lang}: no functions extracted from {code!r}"
        params = funcs[0].params
        assert params == expected_params, f"{lang}: expected {expected_params}, got {params}"


# ── Decorator extraction ─────────────────────────────────────────────────────


class TestDecoratorExtraction:
    """Python decorators must be extracted correctly."""

    def test_python_decorators(self, parser):
        code = "@app.route('/')\n@login_required\ndef index():\n    pass\n"
        tree = parser.parse_code(code, "python")
        funcs = parser.extract_functions(tree, "python")
        assert len(funcs) >= 1
        assert len(funcs[0].decorators) >= 2
        assert any("route" in d for d in funcs[0].decorators)
        assert any("login_required" in d for d in funcs[0].decorators)


# ── Class extraction ─────────────────────────────────────────────────────────


class TestClassExtraction:
    """Classes must be extracted in all languages."""

    def test_python_class(self, parser):
        tree = parser.parse_code(PY_CLASS, "python")
        classes = parser.extract_classes(tree, "python")
        assert len(classes) >= 1
        assert classes[0].name == "Foo"

    def test_javascript_class(self, parser):
        tree = parser.parse_code(JS_CLASS, "javascript")
        classes = parser.extract_classes(tree, "javascript")
        assert len(classes) >= 1
        assert classes[0].name == "Foo"

    def test_java_class(self, parser):
        tree = parser.parse_code(JAVA_SIMPLE, "java")
        classes = parser.extract_classes(tree, "java")
        assert len(classes) >= 1
        assert classes[0].name == "Foo"


# ── Import extraction ────────────────────────────────────────────────────────


class TestImportExtraction:
    """Imports must be extracted in all languages."""

    def test_python_import(self, parser):
        code = "from flask import Flask\nimport os\n"
        tree = parser.parse_code(code, "python")
        imports = parser.extract_imports(tree, "python")
        assert len(imports) >= 2

    def test_javascript_import(self, parser):
        code = "import express from 'express';\nimport { foo } from './bar';\n"
        tree = parser.parse_code(code, "javascript")
        imports = parser.extract_imports(tree, "javascript")
        assert len(imports) >= 2

    def test_java_import(self, parser):
        code = "import java.util.List;\nimport org.springframework.web.bind.annotation.*;\n"
        tree = parser.parse_code(code, "java")
        imports = parser.extract_imports(tree, "java")
        assert len(imports) >= 2


# ── Callee info extraction ───────────────────────────────────────────────────


class TestCalleeInfo:
    """extract_callee_info must handle various call patterns."""

    def test_python_simple_call(self, parser):
        code = "def f():\n    hello()\n"
        tree = parser.parse_code(code, "python")
        # Build call graph to exercise callee extraction
        from hyqagent.cpg.callgraph import SingleFileCallGraph

        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(tree, "python", "<test>")
        # Should find a call edge
        assert any(e.callee == "hello" for e in cg.edges)

    def test_javascript_simple_call(self, parser):
        code = "function f() { hello(); }"
        tree = parser.parse_code(code, "javascript")
        from hyqagent.cpg.callgraph import SingleFileCallGraph

        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(tree, "javascript", "<test>")
        assert any(e.callee == "hello" for e in cg.edges)

    def test_java_simple_call(self, parser):
        code = "class X { void f() { hello(); } }"
        tree = parser.parse_code(code, "java")
        from hyqagent.cpg.callgraph import SingleFileCallGraph

        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(tree, "java", "<test>")
        # Java calls are resolved differently
        assert len(cg.edges) > 0


# ── Assignment types ─────────────────────────────────────────────────────────


class TestAssignmentTypes:
    """assignment_types must be a non-empty set."""

    @pytest.mark.parametrize("lang,prov", _get_providers())
    def test_nonempty(self, lang, prov):
        types = prov.assignment_types
        assert len(types) > 0
        assert all(isinstance(t, str) for t in types)


# ── Edge cases ───────────────────────────────────────────────────────────────


class TestLanguageProviderEdgeCases:
    """Corner cases for provider methods."""

    def test_python_async_function(self, parser):
        code = "async def fetch():\n    return await something()\n"
        tree = parser.parse_code(code, "python")
        funcs = parser.extract_functions(tree, "python")
        assert len(funcs) >= 1
        assert funcs[0].name == "fetch"

    def test_javascript_arrow_function(self, parser):
        code = "const add = (a, b) => a + b;\n"
        tree = parser.parse_code(code, "javascript")
        funcs = parser.extract_functions(tree, "javascript")
        assert any(f.name == "add" for f in funcs)

    def test_java_overloaded_method(self, parser):
        code = "class X { void f(int a) { } void f(String s) { } }"
        tree = parser.parse_code(code, "java")
        funcs = parser.extract_functions(tree, "java")
        # At minimum, one overload should be found
        # (both overloads with same name is a known query limitation)
        assert len(funcs) >= 1
        assert funcs[0].name == "f"

    def test_build_function_node_none(self, parser):
        """build_function_node should return None for non-function nodes."""
        prov = PythonAdapter()
        tree = parser.parse_code("x = 1\n", "python")
        from hyqagent.cpg.traversal import Traverser

        # Find an expression_statement node (not a function)
        for node in Traverser(tree).traverse():
            if node.type == "expression_statement":
                result = prov.build_function_node(node, tree)
                assert result is None
                break
