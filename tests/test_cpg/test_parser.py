"""tests/test_cpg/test_parser.py — Tests for cpg/parser.py.

Covers parse_file, parse_code, extract_functions, extract_classes,
extract_imports across Python, JavaScript, and Java.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tree_sitter import Tree

from hyqagent.cpg.parser import ClassNode, FunctionNode, ImportNode, Parser

FIXTURES = Path(__file__).parent / "fixtures"


# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


@pytest.fixture(scope="module")
def py_tree(parser: Parser) -> Tree:
    return parser.parse_file(FIXTURES / "sample.py")


@pytest.fixture(scope="module")
def js_tree(parser: Parser) -> Tree:
    return parser.parse_file(FIXTURES / "sample.js")


@pytest.fixture(scope="module")
def java_tree(parser: Parser) -> Tree:
    return parser.parse_file(FIXTURES / "sample.java")


# ── Construction ────────────────────────────────────────────────────────


class TestParserConstruction:
    def test_default_languages(self) -> None:
        p = Parser()
        assert len(p._parsers) == 3
        for lang in ("python", "javascript", "java"):
            assert lang in p._parsers

    def test_subset_languages(self) -> None:
        p = Parser(languages=["python"])
        assert len(p._parsers) == 1
        assert "python" in p._parsers
        assert "java" not in p._parsers

    def test_unsupported_language_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported language"):
            Parser(languages=["ruby"])


# ── parse_file ─────────────────────────────────────────────────────────


class TestParseFile:
    def test_parse_python(self, py_tree: Tree) -> None:
        assert py_tree.root_node.type == "module"

    def test_parse_javascript(self, js_tree: Tree) -> None:
        assert js_tree.root_node.type == "program"

    def test_parse_java(self, java_tree: Tree) -> None:
        assert java_tree.root_node.type == "program"

    def test_missing_file(self, parser: Parser) -> None:
        with pytest.raises(FileNotFoundError):
            parser.parse_file("/nonexistent/path.py")

    def test_unknown_extension(self, parser: Parser, tmp_path: Path) -> None:
        bad = tmp_path / "foo.xyz"
        bad.write_text("hello")
        with pytest.raises(ValueError, match="Cannot detect language"):
            parser.parse_file(bad)


# ── parse_code ─────────────────────────────────────────────────────────


class TestParseCode:
    def test_python(self, parser: Parser) -> None:
        tree = parser.parse_code("def foo(): pass", "python")
        assert tree.root_node.type == "module"

    def test_javascript(self, parser: Parser) -> None:
        tree = parser.parse_code("function foo() {}", "javascript")
        assert tree.root_node.type == "program"

    def test_java(self, parser: Parser) -> None:
        tree = parser.parse_code("class Foo {}", "java")
        assert tree.root_node.type == "program"

    def test_uninitialised_language(self) -> None:
        p = Parser(languages=["python"])
        with pytest.raises(ValueError, match="not initialised"):
            p.parse_code("class Foo {}", "java")


# ── extract_functions — Python ─────────────────────────────────────────


class TestExtractPythonFunctions:
    def test_count(self, py_tree: Tree, parser: Parser) -> None:
        funcs = parser.extract_functions(py_tree)
        names = {f.name for f in funcs}
        assert "login" in names
        assert "__init__" in names
        assert "get_user" in names
        assert "list_users" in names
        assert "delete_all" in names

    def test_function_has_params(self, py_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(py_tree)}
        assert funcs["login"].params == []
        assert funcs["__init__"].params == ["db", "config"]
        assert funcs["get_user"].params == ["user_id"]
        assert funcs["list_users"].params == ["limit"]

    def test_method_has_class_name(self, py_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(py_tree)}
        assert funcs["__init__"].is_method is True
        assert funcs["__init__"].class_name == "UserService"
        assert funcs["delete_all"].class_name == "AdminService"

    def test_decorated_function(self, py_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(py_tree)}
        assert len(funcs["login"].decorators) >= 1
        assert any("route" in d for d in funcs["login"].decorators)

    def test_top_level_function_is_not_method(self, py_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(py_tree)}
        assert not funcs["login"].is_method

    def test_line_numbers(self, py_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(py_tree)}
        for f in funcs.values():
            assert f.start_line >= 1
            assert f.end_line >= f.start_line
            assert len(f.source) > 0


# ── extract_functions — JavaScript ─────────────────────────────────────


class TestExtractJSFunctions:
    def test_function_declarations(self, js_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(js_tree)}
        assert "getUser" in funcs
        assert "createUser" in funcs
        assert funcs["getUser"].params == ["id"]
        assert funcs["createUser"].params == ["data"]

    def test_class_methods(self, js_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(js_tree)}
        assert "constructor" in funcs
        assert "componentDidMount" in funcs
        assert "render" in funcs
        assert funcs["constructor"].is_method is True
        assert funcs["constructor"].class_name == "UserComponent"

    def test_arrow_functions(self, js_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(js_tree)}
        assert "handler" in funcs
        assert "foo" in funcs
        assert funcs["handler"].params == ["req", "res"]
        assert funcs["foo"].params == []


# ── extract_functions — Java ───────────────────────────────────────────


class TestExtractJavaMethods:
    def test_method_declarations(self, java_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(java_tree)}
        assert "UserService" in funcs  # constructor
        assert "getUser" in funcs
        assert "listUsers" in funcs
        assert "validate" in funcs

    def test_method_params(self, java_tree: Tree, parser: Parser) -> None:
        funcs = {f.name: f for f in parser.extract_functions(java_tree)}
        assert funcs["getUser"].params == ["userId"]
        assert funcs["listUsers"].params == ["limit"]
        assert funcs["UserService"].params == ["db"]

    def test_all_methods_belong_to_class(self, java_tree: Tree, parser: Parser) -> None:
        funcs = parser.extract_functions(java_tree)
        for f in funcs:
            assert f.is_method is True
            assert f.class_name == "UserService"


# ── extract_classes — Python ───────────────────────────────────────────


class TestExtractPythonClasses:
    def test_count(self, py_tree: Tree, parser: Parser) -> None:
        classes = {c.name: c for c in parser.extract_classes(py_tree)}
        assert "UserService" in classes
        assert "AdminService" in classes

    def test_base_classes(self, py_tree: Tree, parser: Parser) -> None:
        classes = {c.name: c for c in parser.extract_classes(py_tree)}
        assert classes["AdminService"].base_classes == ["UserService"]

    def test_line_numbers(self, py_tree: Tree, parser: Parser) -> None:
        classes = parser.extract_classes(py_tree)
        for c in classes:
            assert c.start_line >= 1
            assert c.end_line >= c.start_line
            assert len(c.source) > 0


# ── extract_classes — JavaScript ───────────────────────────────────────


class TestExtractJSClasses:
    def test_class_declaration(self, js_tree: Tree, parser: Parser) -> None:
        classes = {c.name: c for c in parser.extract_classes(js_tree)}
        assert "UserComponent" in classes
        assert classes["UserComponent"].base_classes == ["React.Component"]


# ── extract_classes — Java ─────────────────────────────────────────────


class TestExtractJavaClasses:
    def test_class_declaration(self, java_tree: Tree, parser: Parser) -> None:
        classes = {c.name: c for c in parser.extract_classes(java_tree)}
        assert "UserService" in classes
        assert "BaseService" in classes["UserService"].base_classes
        assert "IUserRepo" in classes["UserService"].base_classes


# ── extract_imports — Python ───────────────────────────────────────────


class TestExtractPythonImports:
    def test_simple_import(self, py_tree: Tree, parser: Parser) -> None:
        imports = parser.extract_imports(py_tree)
        modules = {i.module: i for i in imports}
        assert "os" in modules
        assert modules["os"].names == ["os"]
        assert not modules["os"].is_relative

    def test_import_from(self, py_tree: Tree, parser: Parser) -> None:
        imports = {i.module: i for i in parser.extract_imports(py_tree)}
        assert imports["flask"].names == ["Flask", "request"]

    def test_relative_import(self, py_tree: Tree, parser: Parser) -> None:
        imports = parser.extract_imports(py_tree)
        rel = [i for i in imports if i.is_relative]
        assert len(rel) >= 1
        assert rel[0].module == ".utils"
        assert "helper" in rel[0].names

    def test_wildcard_import(self, py_tree: Tree, parser: Parser) -> None:
        imports = parser.extract_imports(py_tree)
        wild = [i for i in imports if "*" in i.names]
        assert len(wild) == 1
        assert wild[0].module == "typing"

    def test_aliased_import(self, py_tree: Tree, parser: Parser) -> None:
        imports = {i.module: i for i in parser.extract_imports(py_tree)}
        assert "sys" in imports
        assert imports["sys"].names == ["sys"]


# ── extract_imports — JavaScript ───────────────────────────────────────


class TestExtractJSImports:
    def test_named_import(self, js_tree: Tree, parser: Parser) -> None:
        imports = {i.module: i for i in parser.extract_imports(js_tree)}
        assert "react" in imports
        assert "useState" in imports["react"].names
        assert "useEffect" in imports["react"].names

    def test_default_import(self, js_tree: Tree, parser: Parser) -> None:
        imports = {i.module: i for i in parser.extract_imports(js_tree)}
        assert "axios" in imports
        assert "axios" in imports["axios"].names


# ── extract_imports — Java ─────────────────────────────────────────────


class TestExtractJavaImports:
    def test_import_declarations(self, java_tree: Tree, parser: Parser) -> None:
        imports = parser.extract_imports(java_tree)
        modules = {i.module for i in imports}
        assert "java.util.List" in modules
        assert "java.util.ArrayList" in modules
        assert "java.sql.Connection" in modules

    def test_import_names(self, java_tree: Tree, parser: Parser) -> None:
        imports = {i.module: i for i in parser.extract_imports(java_tree)}
        assert imports["java.util.List"].names == ["List"]


# ── Edge cases ────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_file(self, parser: Parser) -> None:
        tree = parser.parse_code("", "python")
        assert tree.root_node.type == "module"
        assert parser.extract_functions(tree) == []
        assert parser.extract_classes(tree) == []
        assert parser.extract_imports(tree) == []

    def test_code_with_syntax_error(self, parser: Parser) -> None:
        """tree-sitter is error-tolerant — should still produce results."""
        tree = parser.parse_code("def foo(:", "python")
        funcs = parser.extract_functions(tree)
        # Error recovery may or may not find a function — just assert no crash
        assert isinstance(funcs, list)

    def test_nested_functions(self, parser: Parser) -> None:
        code = "def outer():\n    def inner():\n        pass\n    return inner\n"
        tree = parser.parse_code(code, "python")
        funcs = parser.extract_functions(tree)
        names = {f.name for f in funcs}
        # Currently we only extract top-level functions
        assert "outer" in names

    def test_language_is_cached_on_tree(self, parser: Parser) -> None:
        tree = parser.parse_code("def foo(): pass", "python")
        # Implicit language should work
        funcs = parser.extract_functions(tree)
        assert len(funcs) == 1
        assert funcs[0].name == "foo"

    def test_explicit_language_override(self, parser: Parser) -> None:
        tree = parser.parse_code("function foo() {}", "javascript")
        funcs = parser.extract_functions(tree, language="javascript")
        assert len(funcs) == 1
        assert funcs[0].name == "foo"

    def test_node_types(self, py_tree: Tree, parser: Parser) -> None:
        funcs = parser.extract_functions(py_tree)
        for f in funcs:
            assert isinstance(f, FunctionNode)
        classes = parser.extract_classes(py_tree)
        for c in classes:
            assert isinstance(c, ClassNode)
        imports = parser.extract_imports(py_tree)
        for i in imports:
            assert isinstance(i, ImportNode)
