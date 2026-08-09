"""tests/test_scanner/test_sandbox.py — Unit tests for dynamic verification sandbox."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hyqagent.scanner.sandbox import (
    DynamicVerificationResult,
    PocCode,
    PocGenerator,
    SandboxExecutor,
    SandboxResult,
    _build_interpretation_prompt,
    _build_poc_generation_prompt,
    _language_config,
    verify_finding,
    verify_findings,
)

# ── Data model tests ────────────────────────────────────────────────────────


class TestSandboxResult:
    """Tests for the SandboxResult dataclass."""

    def test_defaults(self) -> None:
        r = SandboxResult(finding_id="f1", success=False)
        assert r.finding_id == "f1"
        assert r.success is False
        assert r.exit_code == -1
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.timed_out is False

    def test_successful_execution(self) -> None:
        r = SandboxResult(
            finding_id="f2",
            success=True,
            exit_code=0,
            stdout="PoC confirmed\n[VULNERABLE]\n",
            execution_time_ms=123.4,
        )
        assert r.success is True
        assert "VULNERABLE" in r.stdout

    def test_timeout(self) -> None:
        r = SandboxResult(
            finding_id="f3",
            success=False,
            timed_out=True,
            error="Execution timed out after 30s",
        )
        assert r.timed_out is True
        assert "timed out" in r.error


class TestPocCode:
    """Tests for the PocCode dataclass."""

    def test_minimal(self) -> None:
        p = PocCode(
            finding_id="f1",
            language="python",
            code="print('hello')",
            expected_behavior="Prints hello and exits 0",
        )
        assert p.language == "python"
        assert p.risk_level == "safe"
        assert p.reasoning == ""

    def test_with_reasoning(self) -> None:
        p = PocCode(
            finding_id="f2",
            language="python",
            code="import os; os.system('id')",
            expected_behavior="Executes id command",
            risk_level="read_only",
            reasoning="Demonstrates command injection without side effects",
        )
        assert p.risk_level == "read_only"
        assert "command injection" in p.reasoning


class TestDynamicVerificationResult:
    """Tests for the DynamicVerificationResult dataclass."""

    def test_minimal_inconclusive(self) -> None:
        r = DynamicVerificationResult(
            finding_id="f1",
            vuln_type="sqli",
            severity="high",
        )
        assert r.verdict == "inconclusive"
        assert r.updated_confidence == 0.0
        assert r.execution is None

    def test_full_result(self) -> None:
        exec_result = SandboxResult(finding_id="f1", success=True, exit_code=0)
        r = DynamicVerificationResult(
            finding_id="f1",
            vuln_type="cmdi",
            severity="critical",
            poc_code="print('poc')",
            execution=exec_result,
            verdict="confirmed",
            updated_confidence=0.92,
            reasoning="PoC output matches expected behavior",
            model="claude-opus-5",
        )
        assert r.verdict == "confirmed"
        assert r.updated_confidence == 0.92
        assert r.execution is not None
        assert r.execution.exit_code == 0


# ── _language_config tests ──────────────────────────────────────────────────


class TestLanguageConfig:
    """Tests for the _language_config helper."""

    def test_python(self) -> None:
        ext, cmd = _language_config("python")
        assert ext == ".py"
        assert cmd == ["python3"]

    def test_javascript(self) -> None:
        ext, cmd = _language_config("javascript")
        assert ext == ".js"
        assert cmd == ["node"]

    def test_java(self) -> None:
        ext, cmd = _language_config("java")
        assert ext == ".java"
        assert cmd == ["java"]

    def test_unknown_falls_back_to_python(self) -> None:
        ext, cmd = _language_config("ruby")
        assert ext == ".py"
        assert cmd == ["python3"]


# ── Prompt builder tests ────────────────────────────────────────────────────


class TestBuildPocGenerationPrompt:
    """Tests for _build_poc_generation_prompt."""

    def test_minimal_finding(self) -> None:
        finding = {
            "vuln_type": "sqli",
            "severity": "critical",
            "source_location": "app.py:42",
            "sink_location": "db.py:10",
            "description": "User input flows to SQL query",
        }
        prompt = _build_poc_generation_prompt(finding)
        assert "sqli" in prompt
        assert "critical" in prompt
        assert "app.py:42" in prompt
        assert "db.py:10" in prompt
        assert "SAFE" in prompt

    def test_with_code_context(self) -> None:
        finding = {"vuln_type": "xss", "severity": "high", "description": "..."}
        prompt = _build_poc_generation_prompt(finding, code_context="def foo(): pass")
        assert "def foo(): pass" in prompt
        assert "Code Context" in prompt

    def test_uses_language_field(self) -> None:
        finding = {"vuln_type": "cmdi", "severity": "high", "language": "javascript"}
        prompt = _build_poc_generation_prompt(finding)
        assert "javascript" in prompt


class TestBuildInterpretationPrompt:
    """Tests for _build_interpretation_prompt."""

    def test_basic_structure(self) -> None:
        result = SandboxResult(
            finding_id="f1",
            success=True,
            exit_code=0,
            stdout="[VULNERABLE]\n",
        )
        prompt = _build_interpretation_prompt(
            "print('poc')",
            result,
            "Should print VULNERABLE",
            "cmdi",
        )
        assert "PoC Code Executed" in prompt
        assert "[VULNERABLE]" in prompt
        assert "Exit Code" in prompt
        assert "cmdi" in prompt

    def test_truncates_long_code(self) -> None:
        result = SandboxResult(finding_id="f1", success=False)
        long_code = "x" * 3000
        prompt = _build_interpretation_prompt(
            long_code,
            result,
            "nothing",
            "sqli",
        )
        assert len(prompt) < 5000  # Should be truncated


# ── SandboxExecutor tests (mocked Docker) ───────────────────────────────────


class TestSandboxExecutorMocked:
    """Tests for SandboxExecutor with mocked Docker SDK."""

    @pytest.fixture
    def executor(self) -> SandboxExecutor:
        return SandboxExecutor(image="test-sandbox:latest", timeout=10)

    @pytest.fixture
    def mock_docker_client(self) -> MagicMock:
        client = MagicMock()
        container = MagicMock()
        container.wait.return_value = {"StatusCode": 0}
        container.logs.side_effect = [
            b"PoC output\n[VULNERABLE]\n",  # stdout
            b"",  # stderr
        ]
        client.containers.run.return_value = container
        client.images.get.return_value = MagicMock()
        return client

    def test_execute_success(
        self,
        executor: SandboxExecutor,
        mock_docker_client: MagicMock,
    ) -> None:
        with patch("docker.from_env", return_value=mock_docker_client):
            result = executor._execute_sync(
                "print('hello')",
                "python",
                None,
            )
        assert result.success is True
        assert result.exit_code == 0
        assert "VULNERABLE" in result.stdout
        assert result.timed_out is False

    def test_execute_timeout(
        self,
        executor: SandboxExecutor,
        mock_docker_client: MagicMock,
    ) -> None:
        container = mock_docker_client.containers.run.return_value
        container.wait.side_effect = Exception("Read timed out")

        with patch("docker.from_env", return_value=mock_docker_client):
            result = executor._execute_sync(
                "import time; time.sleep(999)",
                "python",
                None,
            )
        assert result.timed_out is True
        assert result.success is False

    def test_execute_image_not_found(
        self,
        executor: SandboxExecutor,
        mock_docker_client: MagicMock,
    ) -> None:
        from docker.errors import ImageNotFound

        mock_docker_client.images.get.side_effect = ImageNotFound("not found")

        with patch("docker.from_env", return_value=mock_docker_client):
            result = executor._execute_sync(
                "print('x')",
                "python",
                None,
            )
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_execute_docker_unavailable(self, executor: SandboxExecutor) -> None:
        from docker.errors import DockerException

        with patch(
            "docker.from_env",
            side_effect=DockerException("Docker daemon not running"),
        ):
            result = executor._execute_sync(
                "print('x')",
                "python",
                None,
            )
        assert result.success is False
        assert "unavailable" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_async_wraps_sync(
        self,
        executor: SandboxExecutor,
        mock_docker_client: MagicMock,
    ) -> None:
        with patch("docker.from_env", return_value=mock_docker_client):
            result = await executor.execute("print('async')", "python")
        assert result.success is True


# ── PocGenerator tests (mocked LLM) ─────────────────────────────────────────


class TestPocGenerator:
    """Tests for PocGenerator with mocked LLM provider."""

    @pytest.fixture
    def mock_provider(self) -> AsyncMock:
        provider = AsyncMock()
        provider.generate_structured = AsyncMock()
        return provider

    @pytest.fixture
    def generator(self, mock_provider: AsyncMock) -> PocGenerator:
        return PocGenerator(provider=mock_provider, model="claude-opus-5")

    @pytest.mark.asyncio
    async def test_generate_returns_poc_code(
        self,
        mock_provider: AsyncMock,
    ) -> None:
        from hyqagent.scanner.sandbox import PocGenerator

        mock_provider.generate_structured.return_value = {
            "language": "python",
            "code": "import os; os.system('id')",
            "expected_behavior": "Executes id and prints user info",
            "risk_level": "read_only",
            "reasoning": "This is a standard command injection PoC",
        }
        gen = PocGenerator(mock_provider, "claude-opus-5")
        finding = {"id": "f1", "vuln_type": "cmdi", "severity": "critical"}

        poc = await gen.generate(finding)
        assert poc is not None
        assert poc.language == "python"
        assert "os.system" in poc.code
        assert poc.risk_level == "read_only"

    @pytest.mark.asyncio
    async def test_generate_returns_none_on_error(
        self,
        mock_provider: AsyncMock,
    ) -> None:
        from hyqagent.scanner.sandbox import PocGenerator

        mock_provider.generate_structured.side_effect = Exception("API error")
        gen = PocGenerator(mock_provider, "claude-opus-5")

        poc = await gen.generate({"id": "f1", "vuln_type": "sqli"})
        assert poc is None

    @pytest.mark.asyncio
    async def test_interpret_confirmed(
        self,
        mock_provider: AsyncMock,
    ) -> None:
        from hyqagent.scanner.sandbox import PocGenerator

        mock_provider.generate_structured.return_value = {
            "verdict": "confirmed",
            "updated_confidence": 0.91,
            "reasoning": "Stdout shows [VULNERABLE] and exit code is 0",
        }
        gen = PocGenerator(mock_provider, "claude-opus-5")
        result = SandboxResult(
            finding_id="f1",
            success=True,
            exit_code=0,
            stdout="[VULNERABLE]\n",
        )

        interpretation = await gen.interpret(
            "print('poc')",
            result,
            "Should print VULNERABLE",
            "cmdi",
        )
        assert interpretation["verdict"] == "confirmed"
        assert interpretation["updated_confidence"] == 0.91

    @pytest.mark.asyncio
    async def test_interpret_fallback_on_error(
        self,
        mock_provider: AsyncMock,
    ) -> None:
        from hyqagent.scanner.sandbox import PocGenerator

        mock_provider.generate_structured.side_effect = Exception("API error")
        gen = PocGenerator(mock_provider, "claude-opus-5")
        result = SandboxResult(finding_id="f1", success=False)

        interpretation = await gen.interpret(
            "code",
            result,
            "expected",
            "sqli",
        )
        assert interpretation["verdict"] == "inconclusive"
        assert interpretation["updated_confidence"] == 0.5


# ── verify_finding / verify_findings tests ──────────────────────────────────


class TestVerifyFinding:
    """Tests for the top-level verify_finding orchestration function."""

    @pytest.fixture
    def mock_executor(self) -> AsyncMock:
        exec_mock = AsyncMock()
        exec_mock.execute = AsyncMock(
            return_value=SandboxResult(
                finding_id="f1",
                success=True,
                exit_code=0,
                stdout="[VULNERABLE]\n",
            )
        )
        return exec_mock

    @pytest.fixture
    def mock_generator(self) -> AsyncMock:
        gen_mock = AsyncMock()
        gen_mock._model = "test-model"
        gen_mock.generate = AsyncMock(
            return_value=PocCode(
                finding_id="f1",
                language="python",
                code="print('poc')",
                expected_behavior="Prints poc",
            )
        )
        gen_mock.interpret = AsyncMock(
            return_value={
                "verdict": "confirmed",
                "updated_confidence": 0.88,
                "reasoning": "Output matches",
            }
        )
        return gen_mock

    @pytest.mark.asyncio
    async def test_verify_finding_full_pipeline(
        self,
        mock_executor: AsyncMock,
        mock_generator: AsyncMock,
    ) -> None:
        finding = {
            "id": "f1",
            "vuln_type": "cmdi",
            "severity": "critical",
            "source_location": "app.py:10",
            "description": "Command injection in run_cmd()",
        }
        result = await verify_finding(
            finding,
            mock_executor,
            mock_generator,
            language="python",
        )
        assert result.verdict == "confirmed"
        assert result.updated_confidence == 0.88
        assert result.finding_id == "f1"
        assert result.vuln_type == "cmdi"

    @pytest.mark.asyncio
    async def test_verify_finding_poc_generation_fails(
        self,
        mock_executor: AsyncMock,
        mock_generator: AsyncMock,
    ) -> None:
        mock_generator.generate.return_value = None

        result = await verify_finding(
            {"id": "f1", "vuln_type": "sqli", "severity": "high"},
            mock_executor,
            mock_generator,
        )
        assert result.verdict == "inconclusive"
        assert "generation failed" in result.reasoning.lower()

    @pytest.mark.asyncio
    async def test_verify_findings_concurrent(
        self,
        mock_executor: AsyncMock,
        mock_generator: AsyncMock,
    ) -> None:
        findings = [{"id": f"f{i}", "vuln_type": "sqli", "severity": "high"} for i in range(3)]
        results = await verify_findings(
            findings,
            mock_executor,
            mock_generator,
            concurrency=2,
        )
        assert len(results) == 3
        assert all(r.verdict == "confirmed" for r in results)


# ── SandboxExecutor init tests ──────────────────────────────────────────────


class TestSandboxExecutorInit:
    """Tests for SandboxExecutor constructor and defaults."""

    def test_default_values(self) -> None:
        ex = SandboxExecutor()
        assert ex._image == "hyqagent-sandbox:latest"
        assert ex._timeout == 30
        assert ex._memory_limit == "256m"
        assert ex._cpu_quota == 50000

    def test_custom_values(self) -> None:
        ex = SandboxExecutor(
            image="custom:latest",
            timeout=60,
            memory_limit="512m",
            cpu_quota=25000,
        )
        assert ex._image == "custom:latest"
        assert ex._timeout == 60
        assert ex._memory_limit == "512m"
        assert ex._cpu_quota == 25000
