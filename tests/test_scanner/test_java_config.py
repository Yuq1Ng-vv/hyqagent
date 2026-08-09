"""Tests for scanner/java_config.py — JavaConfigScanner."""

from __future__ import annotations

import tempfile
from pathlib import Path

from hyqagent.scanner.java_config import (
    JavaConfigScanner,
    JavaProjectMeta,
    _compare_versions,
)


class TestVersionComparison:
    def test_greater_than(self) -> None:
        assert _compare_versions("2.0.0", "1.0.0") is True

    def test_less_than(self) -> None:
        assert _compare_versions("1.0.0", "2.0.0") is False

    def test_equal(self) -> None:
        assert _compare_versions("1.0.0", "1.0.0") is True

    def test_different_lengths(self) -> None:
        assert _compare_versions("2.17.1", "2.17") is True
        assert _compare_versions("2.14", "2.17.1") is False


class TestJavaConfigScanner:
    def test_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = JavaConfigScanner()
            meta = scanner.scan(tmpdir)
            assert isinstance(meta, JavaProjectMeta)
            assert meta.dependencies == []
            assert meta.config == {}

    def test_parse_pom_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>2.7.0</version>
        </dependency>
    </dependencies>
</project>"""
            Path(tmpdir, "pom.xml").write_text(pom)
            scanner = JavaConfigScanner()
            meta = scanner.scan(tmpdir)
            assert len(meta.dependencies) == 1
            assert meta.dependencies[0].group_id == "org.springframework.boot"
            assert meta.dependencies[0].artifact_id == "spring-boot-starter-web"
            assert meta.dependencies[0].version == "2.7.0"

    def test_detect_log4shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>"""
            Path(tmpdir, "pom.xml").write_text(pom)
            scanner = JavaConfigScanner()
            meta = scanner.scan(tmpdir)
            assert len(meta.warnings) >= 1
            assert any("Log4Shell" in w for w in meta.warnings)

    def test_detect_fastjson(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.80</version>
        </dependency>
    </dependencies>
</project>"""
            Path(tmpdir, "pom.xml").write_text(pom)
            scanner = JavaConfigScanner()
            meta = scanner.scan(tmpdir)
            assert any("Fastjson" in w for w in meta.warnings)

    def test_safe_version_no_warning(self) -> None:
        """A version >= min_safe_version should not trigger a warning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pom = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.17.1</version>
        </dependency>
    </dependencies>
</project>"""
            Path(tmpdir, "pom.xml").write_text(pom)
            scanner = JavaConfigScanner()
            meta = scanner.scan(tmpdir)
            assert len(meta.warnings) == 0

    def test_parse_application_properties(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            props = "server.port=8080\nspring.application.name=test\n"
            Path(tmpdir, "application.properties").write_text(props)
            scanner = JavaConfigScanner()
            meta = scanner.scan(tmpdir)
            assert meta.config.get("server.port") == "8080"
            assert meta.config.get("spring.application.name") == "test"

    def test_parse_application_yml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            yml = """
spring:
  datasource:
    url: jdbc:mysql://localhost/db
server:
  port: 8080
"""
            Path(tmpdir, "application.yml").write_text(yml)
            scanner = JavaConfigScanner()
            meta = scanner.scan(tmpdir)
            assert meta.config.get("spring.datasource.url") == "jdbc:mysql://localhost/db"
            assert meta.config.get("server.port") == "8080"

    def test_detect_dangerous_actuator_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            props = "management.endpoints.web.exposure.include=*\n"
            Path(tmpdir, "application.properties").write_text(props)
            scanner = JavaConfigScanner()
            meta = scanner.scan(tmpdir)
            assert any("Actuator" in w for w in meta.warnings)

    def test_parse_web_xml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            web_xml = """<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1">
    <servlet-mapping>
        <url-pattern>/api/*</url-pattern>
    </servlet-mapping>
    <security-constraint>
        <web-resource-collection>
            <url-pattern>/admin/*</url-pattern>
        </web-resource-collection>
    </security-constraint>
</web-app>"""
            Path(tmpdir, "web.xml").write_text(web_xml)
            scanner = JavaConfigScanner()
            meta = scanner.scan(tmpdir)
            assert len(meta.servlet_mappings) >= 2
            assert "/api/*" in meta.servlet_mappings
            assert any("[SECURED]" in m for m in meta.servlet_mappings)
