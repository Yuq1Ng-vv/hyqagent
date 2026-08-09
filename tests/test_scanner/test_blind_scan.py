"""Tests for scanner/blind_scan.py — BlindScanReviewer, prompt building, schema."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from hyqagent.scanner.blind_scan import (
    BLIND_SCAN_SCHEMA,
    BLIND_SCAN_SYSTEM,
    BlindScanFinding,
    BlindScanResult,
    BlindScanReviewer,
    _build_blind_scan_prompt,
    _endpoint_to_dict,
    exposed_endpoints_from_state,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _mock_provider(response: dict) -> MagicMock:
    """Create a mock AnthropicProvider that returns the given structured response."""
    provider = MagicMock()
    provider.generate_structured = AsyncMock(return_value=response)
    return provider


def _mock_endpoint(**overrides: object) -> MagicMock:
    """Mock an HttpEndpoint object."""
    defaults: dict[str, object] = {
        "route": "/api/users/:id",
        "handler_func": "get_user",
        "methods": ["GET"],
        "file_path": "app.py",
        "line": 42,
        "auth_required": False,
        "framework": "flask",
    }
    defaults.update(overrides)
    return MagicMock(**defaults)


# ── BlindScanFinding ──────────────────────────────────────────────────────────


class TestBlindScanFinding:
    def test_defaults(self) -> None:
        f = BlindScanFinding(
            endpoint="/api/users/:id",
            issue_type="idor",
        )
        assert f.endpoint == "/api/users/:id"
        assert f.issue_type == "idor"
        assert f.severity == "medium"
        assert f.confidence == 0.5
        assert f.title == ""
        assert f.description == ""

    def test_full_fields(self) -> None:
        f = BlindScanFinding(
            endpoint="/api/admin",
            issue_type="missing_auth",
            severity="critical",
            confidence=0.95,
            title="Admin endpoint has no auth",
            description="The /api/admin endpoint lacks any auth decorator.",
            reasoning="No grep rule checks for missing @login_required.",
            cwe_id="CWE-306",
        )
        assert f.severity == "critical"
        assert f.confidence == 0.95
        assert f.cwe_id == "CWE-306"
        assert "No grep rule" in f.reasoning


# ── BlindScanResult ───────────────────────────────────────────────────────────


class TestBlindScanResult:
    def test_defaults(self) -> None:
        r = BlindScanResult()
        assert r.endpoints_reviewed == 0
        assert r.findings == []
        assert r.model == ""
        assert r.reasoning == ""

    def test_with_findings(self) -> None:
        f = BlindScanFinding(endpoint="/api/x", issue_type="idor")
        r = BlindScanResult(
            endpoints_reviewed=5,
            findings=[f],
            model="claude-sonnet-5",
            reasoning="Found 1 issue.",
        )
        assert r.endpoints_reviewed == 5
        assert len(r.findings) == 1
        assert r.model == "claude-sonnet-5"


# ── Schema validation ─────────────────────────────────────────────────────────


class TestBlindScanSchema:
    def test_schema_name(self) -> None:
        assert BLIND_SCAN_SCHEMA["name"] == "report_blind_scan"

    def test_required_fields(self) -> None:
        required = BLIND_SCAN_SCHEMA["input_schema"]["required"]
        assert "endpoints_reviewed" in required
        assert "findings" in required

    def test_finding_properties(self) -> None:
        props = BLIND_SCAN_SCHEMA["input_schema"]["properties"]["findings"]
        item_props = props["items"]["properties"]
        assert "endpoint" in item_props
        assert "issue_type" in item_props
        assert "severity" in item_props
        assert "description" in item_props

    def test_severity_enum(self) -> None:
        props = BLIND_SCAN_SCHEMA["input_schema"]["properties"]["findings"]
        sev = props["items"]["properties"]["severity"]
        assert "enum" in sev
        assert "critical" in sev["enum"]
        assert "high" in sev["enum"]
        assert "medium" in sev["enum"]
        assert "low" in sev["enum"]

    def test_confidence_range(self) -> None:
        props = BLIND_SCAN_SCHEMA["input_schema"]["properties"]["findings"]
        conf = props["items"]["properties"]["confidence"]
        assert conf.get("minimum") == 0.0
        assert conf.get("maximum") == 1.0


# ── System prompt ─────────────────────────────────────────────────────────────


class TestBlindScanSystemPrompt:
    def test_exploratory_role(self) -> None:
        assert "exploratory security auditor" in BLIND_SCAN_SYSTEM.lower()

    def test_pattern_scanners_good_at(self) -> None:
        assert "sql injection" in BLIND_SCAN_SYSTEM.lower()
        assert "xss" in BLIND_SCAN_SYSTEM.lower()

    def test_pattern_scanners_blind_to(self) -> None:
        lower = BLIND_SCAN_SYSTEM.lower()
        assert "idor" in lower
        assert "missing auth" in lower
        assert "business logic" in lower
        assert "race condition" in lower
        assert "mass assignment" in lower

    def test_review_process_steps(self) -> None:
        lower = BLIND_SCAN_SYSTEM.lower()
        assert "resource" in lower
        assert "auth check" in lower
        assert "another user" in lower
        assert "state-changing" in lower
        assert "error path" in lower

    def test_rules_section(self) -> None:
        lower = BLIND_SCAN_SYSTEM.lower()
        assert "only report" in lower
        assert "confidence" in lower
        assert "semantic" in lower

    def test_tool_output_instruction(self) -> None:
        assert "report_blind_scan" in BLIND_SCAN_SYSTEM


# ── Prompt builder ────────────────────────────────────────────────────────────


class TestBuildBlindScanPrompt:
    def test_includes_endpoint_count(self) -> None:
        endpoints = [
            {
                "route": "/api/x",
                "handler_func": "x_handler",
                "methods": ["GET"],
                "file_path": "a.py",
                "line": 1,
                "auth_required": False,
            }
        ]
        prompt = _build_blind_scan_prompt(endpoints)
        assert "1 total" in prompt

    def test_includes_route_and_handler(self) -> None:
        endpoints = [
            {
                "route": "/api/login",
                "handler_func": "do_login",
                "methods": ["POST"],
                "file_path": "auth.py",
                "line": 10,
                "auth_required": False,
            }
        ]
        prompt = _build_blind_scan_prompt(endpoints)
        assert "/api/login" in prompt
        assert "do_login" in prompt

    def test_includes_methods(self) -> None:
        endpoints = [
            {
                "route": "/api/x",
                "handler_func": "x",
                "methods": ["GET", "POST"],
                "file_path": "a.py",
                "line": 1,
                "auth_required": True,
            }
        ]
        prompt = _build_blind_scan_prompt(endpoints)
        assert "GET, POST" in prompt
        assert "**Auth required**: True" in prompt

    def test_includes_framework(self) -> None:
        endpoints = [
            {
                "route": "/api/x",
                "handler_func": "x",
                "methods": ["GET"],
                "file_path": "a.py",
                "line": 1,
                "auth_required": False,
                "framework": "flask",
            }
        ]
        prompt = _build_blind_scan_prompt(endpoints)
        assert "**Framework**: flask" in prompt

    def test_includes_code_context(self) -> None:
        endpoints = [
            {
                "route": "/api/x",
                "handler_func": "do_x",
                "methods": ["GET"],
                "file_path": "a.py",
                "line": 1,
                "auth_required": False,
            }
        ]
        contexts = {"do_x": "def do_x():\n    user = request.args['id']\n    return user"}
        prompt = _build_blind_scan_prompt(endpoints, code_contexts=contexts)
        assert "request.args" in prompt

    def test_missing_code_context_graceful(self) -> None:
        endpoints = [
            {
                "route": "/api/x",
                "handler_func": "no_code",
                "methods": ["GET"],
                "file_path": "a.py",
                "line": 1,
                "auth_required": False,
            }
        ]
        prompt = _build_blind_scan_prompt(endpoints, code_contexts={})
        assert "no_code" in prompt  # still includes handler info

    def test_includes_language(self) -> None:
        endpoints: list[dict] = []
        prompt = _build_blind_scan_prompt(endpoints, language="python")
        assert "**Language**: python" in prompt

    def test_multiple_endpoints(self) -> None:
        endpoints = [
            {
                "route": "/a",
                "handler_func": "fa",
                "methods": ["GET"],
                "file_path": "a.py",
                "line": 1,
                "auth_required": False,
            },
            {
                "route": "/b",
                "handler_func": "fb",
                "methods": ["POST"],
                "file_path": "b.py",
                "line": 5,
                "auth_required": True,
            },
        ]
        prompt = _build_blind_scan_prompt(endpoints)
        assert "2 total" in prompt
        assert "/a" in prompt
        assert "/b" in prompt


# ── Endpoint normalisation ────────────────────────────────────────────────────


class TestEndpointToDict:
    def test_from_http_endpoint(self) -> None:
        ep = _mock_endpoint()
        d = _endpoint_to_dict(ep)
        assert d["route"] == "/api/users/:id"
        assert d["handler_func"] == "get_user"
        assert d["methods"] == ["GET"]
        assert d["auth_required"] is False
        assert d["framework"] == "flask"

    def test_from_dict_passthrough(self) -> None:
        d_in = {"route": "/x", "handler_func": "h"}
        d_out = _endpoint_to_dict(d_in)
        assert d_out is d_in  # same object, passthrough

    def test_missing_attrs_default(self) -> None:
        ep = MagicMock(spec=[])  # object with no attributes
        d = _endpoint_to_dict(ep)
        assert d["route"] == ""
        assert d["methods"] == []


# ── Exposed endpoints extraction ──────────────────────────────────────────────


class TestExposedEndpointsFromState:
    def test_extracts_exposed_endpoints(self) -> None:
        state = MagicMock()
        ep1 = _mock_endpoint(handler_func="covered")
        ep2 = _mock_endpoint(handler_func="exposed")

        # Mock annotated path that covers "covered" handler
        ap = MagicMock()
        ap.path = MagicMock()
        ap.path.nodes = [
            MagicMock(enclosing_function="covered", name=""),
        ]
        state.phase_states = {
            "attack_surface": [ep1, ep2],
            "annotated_paths": [ap],
        }

        result = exposed_endpoints_from_state(state)
        assert len(result) == 1
        assert result[0]["handler_func"] == "exposed"

    def test_all_endpoints_covered_returns_empty(self) -> None:
        state = MagicMock()
        ep = _mock_endpoint(handler_func="only_one")

        ap = MagicMock()
        ap.path = MagicMock()
        ap.path.nodes = [
            MagicMock(enclosing_function="only_one", name=""),
        ]
        state.phase_states = {
            "attack_surface": [ep],
            "annotated_paths": [ap],
        }

        result = exposed_endpoints_from_state(state)
        assert result == []

    def test_empty_state_returns_empty(self) -> None:
        state = MagicMock()
        state.phase_states = {}
        result = exposed_endpoints_from_state(state)
        assert result == []

    def test_no_handler_func_skipped(self) -> None:
        state = MagicMock()
        ep = _mock_endpoint(handler_func="")  # no handler
        state.phase_states = {
            "attack_surface": [ep],
            "annotated_paths": [],
        }

        result = exposed_endpoints_from_state(state)
        assert result == []

    def test_fallback_to_endpoints_key(self) -> None:
        """When 'attack_surface' not in phase_states, try 'endpoints' key."""
        state = MagicMock()
        ep = _mock_endpoint(handler_func="fallback_h")
        state.phase_states = {
            "endpoints": [ep],
            "annotated_paths": [],
        }

        result = exposed_endpoints_from_state(state)
        assert len(result) == 1
        assert result[0]["handler_func"] == "fallback_h"


# ── BlindScanReviewer ─────────────────────────────────────────────────────────


class TestBlindScanReviewerConstruction:
    def test_constructor(self) -> None:
        provider = MagicMock()
        r = BlindScanReviewer(provider=provider, model="claude-sonnet-5")
        assert r._provider is provider
        assert r._model == "claude-sonnet-5"
        assert r._nudge_loop is None

    def test_constructor_with_nudge(self) -> None:
        provider = MagicMock()
        nudge = MagicMock()
        r = BlindScanReviewer(provider=provider, model="m", nudge_loop=nudge)
        assert r._nudge_loop is nudge


class TestBlindScanReviewerReview:
    async def test_empty_endpoints(self) -> None:
        provider = MagicMock()
        r = BlindScanReviewer(provider=provider, model="test-model")
        result = await r.review([])
        assert result.endpoints_reviewed == 0
        assert result.findings == []
        assert "No endpoints" in result.reasoning

    async def test_review_with_mock_llm(self) -> None:
        provider = _mock_provider(
            {
                "endpoints_reviewed": 2,
                "findings": [
                    {
                        "endpoint": "/api/users/:id",
                        "issue_type": "idor",
                        "severity": "high",
                        "confidence": 0.85,
                        "title": "IDOR in user endpoint",
                        "description": "No authorisation check on user ID access.",
                        "reasoning": "Pattern scanners don't understand resource ownership.",
                    }
                ],
            }
        )
        r = BlindScanReviewer(provider=provider, model="test-model")
        endpoints = [
            {
                "route": "/api/users/:id",
                "handler_func": "get_user",
                "methods": ["GET"],
                "file_path": "app.py",
                "line": 42,
                "auth_required": False,
            },
        ]
        result = await r.review(endpoints)

        assert result.endpoints_reviewed == 1  # len(endpoints), not mock val
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.endpoint == "/api/users/:id"
        assert f.issue_type == "idor"
        assert f.severity == "high"
        assert f.confidence == 0.85

    async def test_multiple_findings(self) -> None:
        provider = _mock_provider(
            {
                "endpoints_reviewed": 3,
                "findings": [
                    {
                        "endpoint": "/a",
                        "issue_type": "idor",
                        "severity": "high",
                        "description": "IDOR.",
                    },
                    {
                        "endpoint": "/b",
                        "issue_type": "missing_auth",
                        "severity": "critical",
                        "description": "No auth.",
                    },
                ],
            }
        )
        r = BlindScanReviewer(provider=provider, model="test-model")
        endpoints = [
            {
                "route": "/a",
                "handler_func": "fa",
                "methods": ["GET"],
                "file_path": "x.py",
                "line": 1,
                "auth_required": False,
            }
        ]
        result = await r.review(endpoints)
        assert len(result.findings) == 2

    async def test_llm_failure_returns_graceful(self) -> None:
        provider = MagicMock()
        provider.generate_structured = AsyncMock(side_effect=RuntimeError("API error"))
        r = BlindScanReviewer(provider=provider, model="test-model")
        endpoints = [
            {
                "route": "/x",
                "handler_func": "fx",
                "methods": ["GET"],
                "file_path": "x.py",
                "line": 1,
                "auth_required": False,
            }
        ]
        result = await r.review(endpoints)

        assert result.endpoints_reviewed == 1
        assert result.findings == []
        assert "failed" in result.reasoning

    async def test_diverse_issue_types(self) -> None:
        provider = _mock_provider(
            {
                "endpoints_reviewed": 1,
                "findings": [
                    {
                        "endpoint": "/e",
                        "issue_type": "race_condition",
                        "severity": "medium",
                        "description": "TOCTOU.",
                        "confidence": 0.6,
                    },
                ],
            }
        )
        r = BlindScanReviewer(provider=provider, model="test-model")
        endpoints = [
            {
                "route": "/e",
                "handler_func": "fe",
                "methods": ["POST"],
                "file_path": "e.py",
                "line": 1,
                "auth_required": True,
            }
        ]
        result = await r.review(endpoints)
        assert result.findings[0].issue_type == "race_condition"

    async def test_endpoint_objects_normalized(self) -> None:
        """BlindScanReviewer.review() should accept HttpEndpoint objects."""
        provider = _mock_provider(
            {
                "endpoints_reviewed": 1,
                "findings": [],
            }
        )
        r = BlindScanReviewer(provider=provider, model="test-model")
        ep = _mock_endpoint()
        result = await r.review([ep])
        assert result.endpoints_reviewed == 1

    async def test_missing_fields_default(self) -> None:
        """LLM response missing optional fields → defaults applied."""
        provider = _mock_provider(
            {
                "endpoints_reviewed": 1,
                "findings": [
                    {
                        "endpoint": "/e",
                        "issue_type": "idor",
                        "severity": "high",
                        "description": "test",
                    },
                    # missing: confidence, title, reasoning
                ],
            }
        )
        r = BlindScanReviewer(provider=provider, model="test-model")
        endpoints = [
            {
                "route": "/e",
                "handler_func": "fe",
                "methods": ["GET"],
                "file_path": "e.py",
                "line": 1,
                "auth_required": False,
            }
        ]
        result = await r.review(endpoints)
        f = result.findings[0]
        assert f.confidence == 0.5  # default
        assert f.title == ""
        assert f.reasoning == ""

    async def test_code_contexts_propagated(self) -> None:
        """code_contexts dict is passed through to prompt builder."""
        provider = _mock_provider(
            {
                "endpoints_reviewed": 1,
                "findings": [
                    {
                        "endpoint": "/api/data",
                        "issue_type": "business_logic",
                        "severity": "medium",
                        "description": "logic flaw.",
                    }
                ],
            }
        )
        r = BlindScanReviewer(provider=provider, model="test-model")
        endpoints = [
            {
                "route": "/api/data",
                "handler_func": "get_data",
                "methods": ["GET"],
                "file_path": "data.py",
                "line": 20,
                "auth_required": True,
            }
        ]
        contexts = {"get_data": "def get_data():\n    return db.fetch_all()"}
        result = await r.review(endpoints, code_contexts=contexts)
        assert result.endpoints_reviewed == 1
        assert len(result.findings) == 1

    async def test_language_affects_prompt(self) -> None:
        """Language parameter is passed to prompt builder."""
        provider = _mock_provider(
            {
                "endpoints_reviewed": 1,
                "findings": [],
            }
        )
        r = BlindScanReviewer(provider=provider, model="test-model")
        endpoints = [
            {
                "route": "/x",
                "handler_func": "fx",
                "methods": ["GET"],
                "file_path": "x.java",
                "line": 1,
                "auth_required": False,
            }
        ]
        result = await r.review(endpoints, language="java")
        assert result.endpoints_reviewed == 1


# ── Orchestrator phase integration ────────────────────────────────────────────


class TestPhaseBlindScan:
    async def test_skips_when_no_reviewer(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        state = PipelineState(
            session_id="test-bs",
            current_phase=PhaseName.BLIND_SCAN,
        )
        orch = Orchestrator()  # no blind_scan_reviewer
        await orch._phase_blind_scan(state)
        assert "blind_scan_result" not in state.phase_states

    async def test_skips_quick_mode(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        provider = _mock_provider({"endpoints_reviewed": 0, "findings": []})
        reviewer = BlindScanReviewer(provider=provider, model="test")
        orch = Orchestrator(blind_scan_reviewer=reviewer)

        state = PipelineState(
            session_id="test-bs-q",
            current_phase=PhaseName.BLIND_SCAN,
        )
        state.phase_states["mode"] = "quick"

        await orch._phase_blind_scan(state)
        assert "blind_scan_result" not in state.phase_states

    async def test_skips_when_no_exposed_endpoints(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        provider = _mock_provider({"endpoints_reviewed": 0, "findings": []})
        reviewer = BlindScanReviewer(provider=provider, model="test")
        orch = Orchestrator(blind_scan_reviewer=reviewer)

        state = PipelineState(
            session_id="test-bs-ne",
            current_phase=PhaseName.BLIND_SCAN,
        )
        # No attack_surface or endpoints → exposed_endpoints_from_state returns []
        state.phase_states["attack_surface"] = []
        state.phase_states["annotated_paths"] = []

        await orch._phase_blind_scan(state)
        assert "blind_scan_result" not in state.phase_states

    async def test_stores_result_and_updates_count(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        provider = _mock_provider(
            {
                "endpoints_reviewed": 2,
                "findings": [
                    {
                        "endpoint": "/api/users/:id",
                        "issue_type": "idor",
                        "severity": "high",
                        "description": "IDOR found.",
                    },
                ],
            }
        )
        reviewer = BlindScanReviewer(provider=provider, model="test")
        orch = Orchestrator(blind_scan_reviewer=reviewer)

        state = PipelineState(
            session_id="test-bs-ok",
            current_phase=PhaseName.BLIND_SCAN,
        )
        ep = _mock_endpoint(handler_func="exposed_h")
        state.phase_states["attack_surface"] = [ep]
        state.phase_states["annotated_paths"] = []
        old_fc = state.finding_count

        await orch._phase_blind_scan(state)

        assert "blind_scan_result" in state.phase_states
        result = state.phase_states["blind_scan_result"]
        assert isinstance(result, BlindScanResult)
        assert result.endpoints_reviewed == 1  # len(exposed)
        assert state.finding_count > old_fc

    async def test_phase_name_registered(self) -> None:
        """BLIND_SCAN must be a valid PhaseName."""
        from hyqagent.scanner.orchestrator import DEEP_PHASES, PhaseName

        assert PhaseName.BLIND_SCAN in DEEP_PHASES
        assert PhaseName.BLIND_SCAN.value == "blind_scan"

    async def test_llm_failure_does_not_crash(self) -> None:
        from hyqagent.scanner.orchestrator import Orchestrator, PhaseName, PipelineState

        provider = MagicMock()
        provider.generate_structured = AsyncMock(side_effect=RuntimeError("API down"))
        reviewer = BlindScanReviewer(provider=provider, model="test")
        orch = Orchestrator(blind_scan_reviewer=reviewer)

        state = PipelineState(
            session_id="test-bs-fail",
            current_phase=PhaseName.BLIND_SCAN,
        )
        ep = _mock_endpoint(handler_func="handler_will_fail")
        state.phase_states["attack_surface"] = [ep]
        state.phase_states["annotated_paths"] = []

        # Should not raise — reviewer catches LLM errors internally
        # and returns an empty BlindScanResult, so orchestrator stores it.
        await orch._phase_blind_scan(state)
        # Result is stored — it's an empty BlindScanResult with fail reasoning
        assert "blind_scan_result" in state.phase_states
        result = state.phase_states["blind_scan_result"]
        assert result.findings == []
        assert "failed" in result.reasoning
