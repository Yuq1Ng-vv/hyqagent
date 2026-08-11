"""scanner/java_config.py — Java project configuration scanner.

Parses Maven ``pom.xml``, Spring Boot ``application.properties`` /
``application.yml``, and legacy ``web.xml`` to extract dependency,
configuration, and deployment metadata for security analysis.

All parsing is deterministic — no LLM calls.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Data types ─────────────────────────────────────────────────────────────


@dataclass
class MavenDependency:
    """A single Maven dependency entry."""

    group_id: str
    artifact_id: str
    version: str = ""


@dataclass
class JavaProjectMeta:
    """Aggregated metadata extracted from Java project config files.

    Attributes:
        project_path: Root directory of the Java project.
        dependencies: Discovered Maven dependencies.
        config: Flat key-value pairs from properties / YAML files.
        servlet_mappings: URL patterns from ``web.xml``.
        warnings: Human-readable security findings.

    """

    project_path: str
    dependencies: list[MavenDependency] = field(default_factory=list)
    config: dict[str, str] = field(default_factory=dict)
    servlet_mappings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ── Known-dangerous dependency signatures ───────────────────────────────────

# Each entry is (groupId, artifactId, hint_message, min_safe_version).
_DANGEROUS_DEPS: list[tuple[str, str, str, str | None]] = [
    (
        "org.apache.logging.log4j",
        "log4j-core",
        "Log4Shell — log4j-core < 2.17.1 存在 JNDI 注入 RCE (CVE-2021-44228)",
        "2.17.1",
    ),
    (
        "com.alibaba",
        "fastjson",
        "Fastjson < 1.2.83 存在反序列化 RCE 利用链",
        "1.2.83",
    ),
    (
        "commons-collections",
        "commons-collections",
        "Commons Collections 3.x 存在已知反序列化 gadget chain",
        "3.2.2",
    ),
    (
        "org.apache.struts",
        "struts2-core",
        "Struts2 历史版本存在多个严重 RCE 漏洞 (S2-001 ~ S2-062)",
        None,
    ),
    (
        "org.springframework.boot",
        "spring-boot-starter-actuator",
        "Spring Boot Actuator — 检查是否暴露敏感端点",
        None,
    ),
    (
        "org.apache.commons",
        "commons-text",
        "Apache Commons Text < 1.10.0 存在变量插值 RCE (CVE-2022-42889)",
        "1.10.0",
    ),
    (
        "com.thoughtworks.xstream",
        "xstream",
        "XStream < 1.4.20 存在反序列化 RCE",
        "1.4.20",
    ),
    (
        "org.yaml",
        "snakeyaml",
        "SnakeYAML < 2.0 存在反序列化 RCE",
        "2.0",
    ),
]


def _compare_versions(actual: str, minimum: str) -> bool:
    """Return ``True`` if *actual* >= *minimum* (simple dotted comparison).

    Non-semver versions (e.g. ``${some.prop}``) are treated as vulnerable.
    """
    try:
        a_parts = [int(x) for x in actual.split(".")]
        m_parts = [int(x) for x in minimum.split(".")]
    except (ValueError, TypeError):
        return False  # Unparseable version → treat as vulnerable

    # Pad shorter with zeros
    max_len = max(len(a_parts), len(m_parts))
    a_parts.extend([0] * (max_len - len(a_parts)))
    m_parts.extend([0] * (max_len - len(m_parts)))

    return a_parts >= m_parts


# ── Scanner ─────────────────────────────────────────────────────────────────


class JavaConfigScanner:
    """Scan a Java project directory for configuration files.

    Usage::

        scanner = JavaConfigScanner()
        meta = scanner.scan(Path("/path/to/project"))
        for dep in meta.dependencies:
            print(dep.group_id, dep.artifact_id, dep.version)
        for warn in meta.warnings:
            print("WARNING:", warn)
    """

    # File names we look for
    _POM_FILES = ("pom.xml",)
    _PROPERTY_FILES = ("application.properties", "application.yml", "application.yaml")
    _WEB_XML_FILES = ("web.xml",)

    def scan(self, project_path: str | Path) -> JavaProjectMeta:
        """Scan *project_path* recursively and return aggregated metadata."""
        root = Path(project_path).resolve()
        meta = JavaProjectMeta(project_path=str(root))

        for pom in self._find_files(root, self._POM_FILES):
            self._parse_pom(pom, meta)

        for prop_file in self._find_files(root, self._PROPERTY_FILES):
            self._parse_properties(prop_file, meta)

        for web_xml in self._find_files(root, self._WEB_XML_FILES):
            self._parse_web_xml(web_xml, meta)

        # Check config for dangerous patterns (once, after all files parsed)
        self._check_dangerous_config(meta)

        return meta

    # ── File discovery ──────────────────────────────────────────────────

    @staticmethod
    def _find_files(root: Path, names: tuple[str, ...]) -> list[Path]:
        """Return all files under *root* matching one of *names*."""
        results: list[Path] = []
        for path in root.rglob("*"):
            if path.is_file() and path.name in names:
                # Skip common non-project directories
                if any(
                    part in (".git", "node_modules", "__pycache__", "target", "build")
                    for part in path.parts
                ):
                    continue
                results.append(path)
        return results

    # ── pom.xml ─────────────────────────────────────────────────────────

    def _parse_pom(self, path: Path, meta: JavaProjectMeta) -> None:
        """Extract dependencies from a Maven POM file."""
        try:
            tree = ET.parse(path)  # noqa: S314
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError, OSError):
            return

        # Handle default namespace (http://maven.apache.org/POM/4.0.0)
        ns = self._resolve_namespace(root)

        # Extract dependencies
        deps_elem = root.find(f"{ns}dependencies") if ns else root.find("dependencies")
        if deps_elem is None:
            deps_elem = root  # fallback: search entire POM

        for dep_elem in deps_elem.findall(f"{ns}dependency"):
            gid = self._text(dep_elem.find(f"{ns}groupId"))
            aid = self._text(dep_elem.find(f"{ns}artifactId"))
            ver = self._text(dep_elem.find(f"{ns}version"))

            if gid and aid:
                dep = MavenDependency(group_id=gid, artifact_id=aid, version=ver)
                meta.dependencies.append(dep)

                # Check against dangerous list
                for d_gid, d_aid, hint, min_ver in _DANGEROUS_DEPS:
                    if gid == d_gid and aid == d_aid:
                        if min_ver and ver and _compare_versions(ver, min_ver):
                            continue  # Version is safe
                        meta.warnings.append(
                            f"{path.name}: {hint} (found {gid}:{aid}" + (f":{ver})" if ver else ")")
                        )

        # Also check properties for version placeholders
        props: dict[str, str] = {}
        props_elem = root.find(f"{ns}properties") if ns else root.find("properties")
        if props_elem is not None:
            for prop in list(props_elem):
                tag = prop.tag.replace(ns, "") if ns else prop.tag
                props[tag] = (prop.text or "").strip()

        # Store interesting properties
        for key in ("java.version", "maven.compiler.source", "maven.compiler.target"):
            if key in props:
                meta.config[f"pom:{key}"] = props[key]

    @staticmethod
    def _resolve_namespace(root: Any) -> str:
        """Extract the Maven XML namespace prefix, if any."""
        tag = root.tag
        if "}" in tag:
            ns_url = tag.split("}")[0].lstrip("{")
            return f"{{{ns_url}}}"
        return ""

    @staticmethod
    def _text(elem: Any) -> str:
        """Safe text extraction from an XML element."""
        if elem is None:
            return ""
        return (elem.text or "").strip()

    # ── application.properties / application.yml ────────────────────────

    def _parse_properties(self, path: Path, meta: JavaProjectMeta) -> None:
        """Extract key-value pairs from Spring Boot config files."""
        try:
            content = path.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return

        if path.suffix in (".yml", ".yaml"):
            self._parse_yaml_lite(content, meta)
        else:
            self._parse_dot_properties(content, meta)

    @staticmethod
    def _parse_dot_properties(content: str, meta: JavaProjectMeta) -> None:
        """Parse ``key=value`` (and ``key: value``) properties."""
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("!"):
                continue
            # key=value or key: value
            match = re.match(r"^([^=:]+?)\s*[=:]\s*(.+?)\s*$", stripped)
            if match:
                meta.config[match.group(1).strip()] = match.group(2).strip()

    @staticmethod
    def _parse_yaml_lite(content: str, meta: JavaProjectMeta) -> None:
        """Minimal YAML key-value extraction (flat keys only).

        Handles nested keys by concatenating with ``.`` (e.g.
        ``server:`` / ``  port: 8080`` → ``server.port=8080``).
        Does **not** handle complex YAML lists or anchors.
        """
        prefix_stack: list[str] = []
        for line in content.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue

            indent = len(line) - len(line.lstrip())
            stripped = line.strip()

            # Compute nesting depth (2-space convention)
            depth = indent // 2
            # Trim prefix stack to current depth
            prefix_stack = prefix_stack[:depth]

            if ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip()

                if val:
                    # leaf key: value
                    full_key = ".".join([*prefix_stack, key]) if prefix_stack else key
                    # Unquote if needed
                    val = val.strip("\"'")
                    meta.config[full_key] = val
                else:
                    # nested key → push
                    prefix_stack.append(key)

    def _check_dangerous_config(self, meta: JavaProjectMeta) -> None:
        """Inspect *meta.config* for known-dangerous patterns."""
        checks: list[tuple[str, str]] = [
            (
                "management.endpoints.web.exposure.include",
                "Spring Actuator 全端点暴露 (*) — 可能泄漏堆内存、配置、环境变量等敏感信息",
            ),
            (
                "spring.devtools.restart.enabled",
                "Spring DevTools 在生产环境启用 — 可能允许远程代码修改",
            ),
            (
                "spring.security.enabled",
                "Spring Security 已显式禁用",
            ),
            (
                "security.basic.enabled",
                "Spring Security Basic Auth 已禁用",
            ),
            (
                "endpoints.health.sensitive",
                "Actuator 健康端点敏感信息未脱敏",
            ),
        ]

        for key, warning in checks:
            if key in meta.config:
                val = meta.config[key].lower()
                if (
                    (key == "management.endpoints.web.exposure.include" and "*" in val)
                    or (key == "spring.devtools.restart.enabled" and val in ("true",))
                    or (key == "spring.security.enabled" and val in ("false",))
                    or (key == "security.basic.enabled" and val in ("false",))
                    or (key == "endpoints.health.sensitive" and val in ("false",))
                ):
                    meta.warnings.append(warning)

    # ── web.xml ──────────────────────────────────────────────────────────

    def _parse_web_xml(self, path: Path, meta: JavaProjectMeta) -> None:
        """Extract servlet URL patterns from ``web.xml``."""
        try:
            tree = ET.parse(path)  # noqa: S314
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError, OSError):
            return

        # web.xml may use a default namespace; strip it for element matching.
        def _local_tag(elem: Any) -> str:
            tag = str(elem.tag)
            return tag.split("}")[1] if "}" in tag else tag

        # servlet-mapping → url-pattern
        for elem in root.iter():
            if _local_tag(elem) == "servlet-mapping":
                for child in elem:
                    if _local_tag(child) == "url-pattern" and child.text:
                        meta.servlet_mappings.append(child.text.strip())

        # filter-mapping → url-pattern
        for elem in root.iter():
            if _local_tag(elem) == "filter-mapping":
                for child in elem:
                    if _local_tag(child) == "url-pattern" and child.text:
                        meta.servlet_mappings.append(child.text.strip())

        # security-constraint → web-resource-collection → url-pattern
        for elem in root.iter():
            if _local_tag(elem) == "security-constraint":
                for child in elem.iter():
                    if _local_tag(child) == "web-resource-collection":
                        for sub in child:
                            if _local_tag(sub) == "url-pattern" and sub.text:
                                meta.servlet_mappings.append(f"[SECURED] {sub.text.strip()}")
