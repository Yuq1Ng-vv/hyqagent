"""Tests for Java annotation extraction in JavaAdapter.

Verifies that ``extract_decorators()``, ``build_function_node()``, and
``build_class_node()`` correctly surface Java annotations after the
Session 1.30 annotation extraction fix.
"""

from __future__ import annotations

from hyqagent.cpg.languages.java import JavaAdapter
from hyqagent.cpg.parser import Parser


class TestJavaAnnotationExtraction:
    """Tests for ``JavaAdapter.extract_decorators()``."""

    def test_extract_method_annotations(self) -> None:
        adapter = JavaAdapter()
        code = """
        class X {
            @GetMapping("/path")
            @PreAuthorize("hasRole('USER')")
            public String f() { return "x"; }
        }
        """
        parser = Parser(languages=["java"])
        tree = parser.parse_code(code, "java")
        adapter = parser.get_provider(parser.get_language(tree))

        for node in tree.root_node.children:
            if node.is_named:
                # Find method_declaration
                for child in node.children:
                    if child.is_named:
                        for sub in child.children:
                            if sub.is_named:
                                for method in sub.children:
                                    if method.is_named and method.type == "method_declaration":
                                        decorators = adapter.extract_decorators(method)
                                        assert len(decorators) == 2
                                        assert any("GetMapping" in d for d in decorators)
                                        assert any("PreAuthorize" in d for d in decorators)
                                        return

    def test_extract_marker_annotation(self) -> None:
        """@Override (no args) should be extracted."""
        adapter = JavaAdapter()
        code = """
        class X {
            @Override
            public String toString() { return "X"; }
        }
        """
        parser = Parser(languages=["java"])
        tree = parser.parse_code(code, "java")
        adapter = parser.get_provider(parser.get_language(tree))

        for node in tree.root_node.children:
            if node.is_named:
                for child in node.children:
                    if child.is_named:
                        for sub in child.children:
                            if sub.is_named:
                                for method in sub.children:
                                    if method.is_named and method.type == "method_declaration":
                                        decorators = adapter.extract_decorators(method)
                                        assert len(decorators) == 1
                                        assert "Override" in decorators[0]
                                        return

    def test_no_annotations_returns_empty(self) -> None:
        adapter = JavaAdapter()
        code = """
        class X {
            public String f() { return "x"; }
        }
        """
        parser = Parser(languages=["java"])
        tree = parser.parse_code(code, "java")
        adapter = parser.get_provider(parser.get_language(tree))

        for node in tree.root_node.children:
            if node.is_named:
                for child in node.children:
                    if child.is_named:
                        for sub in child.children:
                            if sub.is_named:
                                for method in sub.children:
                                    if method.is_named and method.type == "method_declaration":
                                        decorators = adapter.extract_decorators(method)
                                        assert decorators == []
                                        return

    def test_extract_class_annotations(self) -> None:
        """@RestController and @RequestMapping on a class should be extracted."""
        adapter = JavaAdapter()
        code = """
        @RestController
        @RequestMapping("/api")
        public class UserController {
            public String f() { return "x"; }
        }
        """
        parser = Parser(languages=["java"])
        tree = parser.parse_code(code, "java")
        adapter = parser.get_provider(parser.get_language(tree))

        for node in tree.root_node.children:
            if node.is_named and node.type == "class_declaration":
                decorators = adapter.extract_decorators(node)
                assert len(decorators) == 2
                assert any("RestController" in d for d in decorators)
                assert any("RequestMapping" in d for d in decorators)
                return

    def test_annotation_with_element_value_pairs(self) -> None:
        """Annotation with named args like @RequestMapping(method=POST)."""
        adapter = JavaAdapter()
        code = """
        class X {
            @RequestMapping(value="/path", method=RequestMethod.POST)
            public String f() { return "x"; }
        }
        """
        parser = Parser(languages=["java"])
        tree = parser.parse_code(code, "java")
        adapter = parser.get_provider(parser.get_language(tree))

        # Just verify it doesn't crash — the annotation text is opaque
        for node in tree.root_node.children:
            if node.is_named:
                for child in node.children:
                    if child.is_named:
                        for sub in child.children:
                            if sub.is_named:
                                for method in sub.children:
                                    if method.is_named and method.type == "method_declaration":
                                        decorators = adapter.extract_decorators(method)
                                        assert len(decorators) == 1
                                        assert "RequestMapping" in decorators[0]
                                        assert "method" in decorators[0]
                                        return

    def test_parameter_annotations_not_in_method_decorators(self) -> None:
        """@RequestParam on a parameter should NOT appear in method decorators."""
        adapter = JavaAdapter()
        code = """
        class X {
            @GetMapping("/path")
            public String f(@RequestParam String name) { return name; }
        }
        """
        parser = Parser(languages=["java"])
        tree = parser.parse_code(code, "java")
        adapter = parser.get_provider(parser.get_language(tree))

        for node in tree.root_node.children:
            if node.is_named:
                for child in node.children:
                    if child.is_named:
                        for sub in child.children:
                            if sub.is_named:
                                for method in sub.children:
                                    if method.is_named and method.type == "method_declaration":
                                        decorators = adapter.extract_decorators(method)
                                        # Only @GetMapping, not @RequestParam
                                        assert len(decorators) == 1
                                        assert "GetMapping" in decorators[0]
                                        return

    def test_build_function_node_has_decorators(self) -> None:
        """FunctionNode built from annotated method should carry decorators."""
        from hyqagent.cpg.traversal import Traverser

        parser = Parser(languages=["java"])
        code = """
        class X {
            @GetMapping("/users")
            public String list() { return "[]"; }
        }
        """
        tree = parser.parse_code(code, "java")
        provider = parser.get_provider(parser.get_language(tree))

        found = False
        for node in Traverser(tree).traverse():
            if node.type == "method_declaration":
                fn = provider.build_function_node(node, tree)
                if fn and fn.name == "list":
                    assert len(fn.decorators) >= 1
                    assert any("GetMapping" in d for d in fn.decorators)
                    found = True
        assert found, "Did not find the 'list' function"

    def test_build_class_node_has_decorators(self) -> None:
        """ClassNode built from annotated class should carry decorators."""
        from hyqagent.cpg.traversal import Traverser

        parser = Parser(languages=["java"])
        code = """
        @RestController
        public class ApiController { }
        """
        tree = parser.parse_code(code, "java")
        provider = parser.get_provider(parser.get_language(tree))

        found = False
        for node in Traverser(tree).traverse():
            if node.type == "class_declaration":
                cn = provider.build_class_node(node, tree)
                if cn and "ApiController" in cn.name:
                    assert any("RestController" in d for d in cn.decorators)
                    found = True
        assert found, "Did not find ApiController class"
