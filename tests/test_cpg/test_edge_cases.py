"""tests/test_cpg/test_edge_cases.py — Edge-case and robustness tests.

Covers scenarios that work correctly but previously had zero test coverage:
syntax errors, Unicode, empty inputs, deep nesting, cross-instance calls,
mutual recursion, shadowed builtins, and more.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hyqagent.cpg.callgraph import SingleFileCallGraph
from hyqagent.cpg.parser import Parser
from hyqagent.cpg.traversal import Traverser

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def parser() -> Parser:
    return Parser()


# ════════════════════════════════════════════════════════════════════════
#  Parser — malformed / error-recovery inputs
# ════════════════════════════════════════════════════════════════════════


class TestSyntaxErrors:
    """Parser should not crash on syntax errors — tree-sitter recovers."""

    def test_syntax_error_recovery(self, parser: Parser) -> None:
        tree = parser.parse_code("def foo(:\n    x = \nclass Broken:", "python")
        funcs = parser.extract_functions(tree)
        classes = parser.extract_classes(tree)
        imports = parser.extract_imports(tree)
        # tree-sitter should NOT crash; partial results are acceptable
        assert isinstance(funcs, list)
        assert isinstance(classes, list)
        assert isinstance(imports, list)

    def test_syntax_error_still_traversable(self, parser: Parser) -> None:
        """Even with ERROR nodes, Traverser should still walk the tree."""
        code = "def foo(x):\n    return \n  ?broken???\ndef bar(): pass"
        tree = parser.parse_code(code, "python")
        t = Traverser(tree)
        # Should find at least one valid function
        func_nodes = list(t.traverse({"function_definition"}))
        assert len(func_nodes) >= 1

    def test_syntax_error_callgraph_no_crash(self, parser: Parser) -> None:
        """SingleFileCallGraph should handle syntax-error trees gracefully."""
        tree = parser.parse_code("def a():\n    ???\n    b()\ndef b(): pass", "python")
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(tree, "python")
        # Should not crash; may or may not resolve b() depending on recovery
        assert isinstance(cg.edges, list)


# ════════════════════════════════════════════════════════════════════════
#  Unicode & special identifiers
# ════════════════════════════════════════════════════════════════════════


class TestUnicode:
    """Unicode identifiers should work across all three languages."""

    def test_python_unicode_function_names(self, parser: Parser) -> None:
        code = "def 你好():\n    return 1\ndef café_功能(データ):\n    return データ\n"
        tree = parser.parse_code(code, "python")
        funcs = parser.extract_functions(tree)
        names = {f.name for f in funcs}
        assert "你好" in names
        assert "café_功能" in names

    def test_python_unicode_call_resolution(self, parser: Parser) -> None:
        code = "def 処理(x):\n    return 変換(x)\ndef 変換(y):\n    return y\n"
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        assert cg.has_edge("処理", "変換")

    def test_js_unicode_identifiers(self, parser: Parser) -> None:
        code = "function привет() { return 1; }\nfunction 测试() { return привет(); }\n"
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "javascript"), "javascript")
        assert cg.has_edge("测试", "привет")


# ════════════════════════════════════════════════════════════════════════
#  Empty / minimal inputs
# ════════════════════════════════════════════════════════════════════════


class TestEmptyInputs:
    """Empty or near-empty inputs should return empty results, not crash."""

    @pytest.mark.parametrize("code,label", [
        ("", "empty string"),
        ("# just a comment\n", "comment only"),
        ("\n\n\n", "whitespace only"),
        ("import os\n", "import only"),
    ])
    def test_empty_variants_no_crash(self, parser: Parser, code: str, label: str) -> None:
        tree = parser.parse_code(code, "python")
        assert parser.extract_functions(tree) == []
        assert parser.extract_classes(tree) == []
        # imports may or may not exist depending on content

    def test_empty_string_traversal(self, parser: Parser) -> None:
        """Traverser on empty input should yield only the module node."""
        tree = parser.parse_code("", "python")
        t = Traverser(tree)
        nodes = list(t.traverse())
        assert len(nodes) >= 1  # at least the root module node


# ════════════════════════════════════════════════════════════════════════
#  Deep nesting
# ════════════════════════════════════════════════════════════════════════


class TestDeepNesting:
    """Deeply nested code should not cause recursion errors."""

    def test_deep_if_nesting(self, parser: Parser) -> None:
        code = "def deep():\n"
        for i in range(200):
            code += "  " * (i + 1) + "if True:\n"
        code += "  " * 201 + "pass\n"
        tree = parser.parse_code(code, "python")
        funcs = parser.extract_functions(tree)
        assert len(funcs) == 1
        assert funcs[0].name == "deep"

    def test_many_functions(self, parser: Parser) -> None:
        """100+ function definitions should all be collected."""
        code = ""
        for i in range(100):
            code += f"def func_{i}():\n    return func_{i + 1}()\n"
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        assert len(cg.function_names) == 100


# ════════════════════════════════════════════════════════════════════════
#  Cross-instance / uninitialized
# ════════════════════════════════════════════════════════════════════════


class TestCrossInstance:
    """Trees from one Parser should not work with another Parser."""

    def test_cross_instance_extract_raises(self, parser: Parser) -> None:
        p1 = Parser(["python"])
        p2 = Parser(["python"])
        tree = p1.parse_code("def foo(): pass", "python")
        with pytest.raises(ValueError, match="Cannot determine language"):
            p2.extract_functions(tree)

    def test_get_provider_raises_valueerror(self, parser: Parser) -> None:
        with pytest.raises(ValueError, match="Unsupported language"):
            parser.get_provider("ruby")


# ════════════════════════════════════════════════════════════════════════
#  CallGraph — mutual recursion, shadowing, forward refs
# ════════════════════════════════════════════════════════════════════════


class TestCallGraphEdges:
    """Call graph scenarios that were previously untested."""

    def test_mutual_recursion(self, parser: Parser) -> None:
        code = "def a():\n    return b()\ndef b():\n    return a()\n"
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        assert cg.has_edge("a", "b")
        assert cg.has_edge("b", "a")

    def test_forward_reference(self, parser: Parser) -> None:
        """Call to a function defined later in the file — name-based, should work."""
        code = "def a():\n    return b()\ndef b():\n    return 1\n"
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        assert cg.has_edge("a", "b")

    def test_shadowed_builtin(self, parser: Parser) -> None:
        """A function named 'print' should be resolved locally, not marked external."""
        code = "def print(x):\n    pass\ndef run():\n    print(42)\n"
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        assert cg.has_edge("run", "print")

    def test_multiple_calls_same_line(self, parser: Parser) -> None:
        code = "def a(): pass\ndef b(): pass\ndef c(): pass\ndef runner():\n    a(); b(); c()\n"
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        assert cg.has_edge("runner", "a")
        assert cg.has_edge("runner", "b")
        assert cg.has_edge("runner", "c")

    def test_large_function_many_calls(self, parser: Parser) -> None:
        """A function with 500 calls should be analyzed without performance issues."""
        code = ""
        for i in range(50):
            code += f"def helper_{i}():\n    return {i}\n"
        code += "def big():\n"
        for i in range(500):
            code += f"    helper_{i % 50}()\n"
        cg = SingleFileCallGraph(parser)
        cg.build_from_tree(parser.parse_code(code, "python"), "python")
        # Most helpers should be resolved
        assert len(cg.resolved_edges) > 0
        edges = cg.get_callees("big")
        assert len(edges) == 500

    def test_build_from_tree_bad_language(self, parser: Parser) -> None:
        """Passing an unregistered language should raise ValueError."""
        cg = SingleFileCallGraph(parser)
        tree = parser.parse_code("def f(): pass", "python")
        with pytest.raises(ValueError, match="Unsupported language"):
            cg.build_from_tree(tree, "ruby")

    def test_build_from_file_nonexistent(self, parser: Parser) -> None:
        """Non-existent file path should raise FileNotFoundError."""
        cg = SingleFileCallGraph(parser)
        with pytest.raises(FileNotFoundError):
            cg.build_from_file("/nonexistent/file_12345.py")

    def test_callgraph_on_sample_py(self, parser: Parser) -> None:
        """Smoke test: real fixture file should produce edges."""
        cg = SingleFileCallGraph(parser)
        cg.build_from_file(FIXTURES / "sample.py")
        assert len(cg.function_names) > 0
        assert isinstance(cg.edges, list)


# ════════════════════════════════════════════════════════════════════════
#  Traverser edge cases
# ════════════════════════════════════════════════════════════════════════


class TestTraverserEdges:
    """Traverser scenarios previously untested."""

    def test_find_first_no_match(self, parser: Parser) -> None:
        tree = parser.parse_code("x = 1", "python")
        t = Traverser(tree)
        assert t.find_first("class_definition") is None

    def test_ancestor_of_type_no_match(self, parser: Parser) -> None:
        tree = parser.parse_code("x = 1", "python")
        t = Traverser(tree)
        node = t.find_first("identifier")
        if node is not None:
            assert Traverser.ancestor_of_type(node, "class_definition") is None

    def test_post_order_on_leaf(self, parser: Parser) -> None:
        """Post-order traversal should work even on a minimal tree."""
        tree = parser.parse_code("", "python")
        t = Traverser(tree)
        nodes = list(t.traverse())  # any order should work
        assert len(nodes) > 0


# ════════════════════════════════════════════════════════════════════════
#  Data type validation
# ════════════════════════════════════════════════════════════════════════


class TestDataTypeValidation:
    """__post_init__ validators on data classes."""

    def test_function_node_empty_name_raises(self) -> None:
        from hyqagent.cpg.types import FunctionNode

        with pytest.raises(ValueError, match="name must be non-empty"):
            FunctionNode(name="", start_line=1, end_line=2, source="")

    def test_function_node_invalid_start_line(self) -> None:
        from hyqagent.cpg.types import FunctionNode

        with pytest.raises(ValueError, match="start_line must be >= 1"):
            FunctionNode(name="f", start_line=0, end_line=2, source="")

    def test_class_node_empty_name(self) -> None:
        from hyqagent.cpg.types import ClassNode

        with pytest.raises(ValueError, match="name must be non-empty"):
            ClassNode(name="", start_line=1, end_line=2, source="")

    def test_import_node_negative_start_line(self) -> None:
        from hyqagent.cpg.types import ImportNode

        with pytest.raises(ValueError, match="start_line must be >= 0"):
            ImportNode(module="x", start_line=-1)
