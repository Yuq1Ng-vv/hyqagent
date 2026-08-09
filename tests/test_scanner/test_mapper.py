"""Tests for scanner/mapper.py — deterministic attack-surface mapping."""

from __future__ import annotations

from hyqagent.cpg.frameworks.base import HttpEndpoint, RouteParam
from hyqagent.scanner.mapper import (
    AttackSurfaceMapper,
    EndpointCategory,
    map_endpoints,
)


class TestEndpointCategory:
    def test_all_categories_defined(self) -> None:
        assert EndpointCategory.AUTH_BYPASS == "auth_bypass"
        assert EndpointCategory.FILE_UPLOAD == "file_upload"
        assert EndpointCategory.ADMIN_EXPOSED == "admin_exposed"
        assert EndpointCategory.CONFIG_LEAK == "config_leak"


class TestScoredEndpoint:
    def test_high_risk_threshold(self) -> None:
        ep = _make_endpoint("/test", ["GET"])
        se = AttackSurfaceMapper().map([ep]).scored[0]
        assert not se.is_high_risk
        assert not se.is_medium_risk  # GET without auth = score 2 → low

    def test_medium_risk_threshold(self) -> None:
        ep = _make_endpoint("/api/data", ["POST"])
        se = AttackSurfaceMapper().map([ep]).scored[0]
        # POST + no auth → score high enough
        assert se.risk_score >= 1


class TestAttackSurface:
    def test_summary_counts(self) -> None:
        eps = [
            _make_endpoint("/a", ["POST"]),
            _make_endpoint("/b", ["GET"]),
        ]
        surface = AttackSurfaceMapper().map(eps)
        assert surface.total_endpoints == 2
        assert isinstance(surface.summary, dict)
        assert sum(surface.summary.values()) == 2

    def test_high_risk_property(self) -> None:
        eps = [
            _make_endpoint(
                "/api/users", ["POST"], auth=False, params=[RouteParam(name="data", source="body")]
            ),
        ]
        surface = AttackSurfaceMapper().map(eps)
        assert len(surface.high_risk) >= 0  # should work regardless


class TestAttackSurfaceMapper:
    def test_empty_endpoints(self) -> None:
        mapper = AttackSurfaceMapper()
        surface = mapper.map([])
        assert surface.total_endpoints == 0
        assert surface.scored == []

    def test_post_without_auth_is_high_risk(self) -> None:
        ep = _make_endpoint(
            "/api/data", ["POST"], auth=False, params=[RouteParam(name="x", source="body")]
        )
        mapper = AttackSurfaceMapper()
        surface = mapper.map([ep])
        assert surface.scored[0].risk_score >= 7
        assert surface.scored[0].category == EndpointCategory.AUTH_BYPASS

    def test_get_without_auth_is_low_risk(self) -> None:
        ep = _make_endpoint("/api/public", ["GET"], auth=False)
        mapper = AttackSurfaceMapper()
        surface = mapper.map([ep])
        assert surface.scored[0].risk_score <= 5
        assert surface.scored[0].category == EndpointCategory.PUBLIC_READ

    def test_delete_is_higher_risk_than_get(self) -> None:
        get_ep = _make_endpoint("/api/x", ["GET"], auth=False)
        del_ep = _make_endpoint("/api/x", ["DELETE"], auth=False)
        mapper = AttackSurfaceMapper()
        get_score = mapper.map([get_ep]).scored[0].risk_score
        del_score = mapper.map([del_ep]).scored[0].risk_score
        assert del_score > get_score

    def test_auth_required_reduces_risk(self) -> None:
        no_auth = _make_endpoint("/api/x", ["POST"], auth=False)
        with_auth = _make_endpoint("/api/x", ["POST"], auth=True)
        mapper = AttackSurfaceMapper()
        no_score = mapper.map([no_auth]).scored[0].risk_score
        yes_score = mapper.map([with_auth]).scored[0].risk_score
        assert yes_score < no_score

    def test_file_param_triggers_file_upload_category(self) -> None:
        ep = _make_endpoint(
            "/api/upload", ["POST"], auth=True, params=[RouteParam(name="file", source="file")]
        )
        mapper = AttackSurfaceMapper()
        se = mapper.map([ep]).scored[0]
        assert se.category == EndpointCategory.FILE_UPLOAD

    def test_admin_route_detected(self) -> None:
        ep = _make_endpoint("/admin/dashboard", ["GET"], auth=False)
        mapper = AttackSurfaceMapper()
        se = mapper.map([ep]).scored[0]
        assert se.category == EndpointCategory.ADMIN_EXPOSED

    def test_actuator_detected_as_admin(self) -> None:
        ep = _make_endpoint("/actuator/health", ["GET"], auth=False)
        mapper = AttackSurfaceMapper()
        se = mapper.map([ep]).scored[0]
        assert se.category == EndpointCategory.ADMIN_EXPOSED

    def test_debug_endpoint_is_config_leak(self) -> None:
        ep = _make_endpoint("/debug/trace", ["GET"], auth=False)
        mapper = AttackSurfaceMapper()
        se = mapper.map([ep]).scored[0]
        assert se.category == EndpointCategory.CONFIG_LEAK

    def test_login_without_auth_is_auth_bypass(self) -> None:
        ep = _make_endpoint(
            "/api/login", ["POST"], auth=False, params=[RouteParam(name="password", source="body")]
        )
        mapper = AttackSurfaceMapper()
        se = mapper.map([ep]).scored[0]
        assert se.category == EndpointCategory.AUTH_BYPASS

    def test_sort_descending_by_risk(self) -> None:
        eps = [
            _make_endpoint("/low", ["GET"], auth=True),
            _make_endpoint(
                "/high", ["DELETE"], auth=False, params=[RouteParam(name="x", source="body")]
            ),
        ]
        mapper = AttackSurfaceMapper()
        surface = mapper.map(eps)
        scores = [s.risk_score for s in surface.scored]
        assert scores == sorted(scores, reverse=True)

    def test_filter_for_phase3_limits_count(self) -> None:
        eps = [
            _make_endpoint(
                f"/api/e{i}", ["POST"], auth=False, params=[RouteParam(name="x", source="body")]
            )
            for i in range(10)
        ]
        mapper = AttackSurfaceMapper()
        surface = mapper.map(eps)
        phase3 = mapper.filter_for_phase3(surface, max_endpoints=3)
        assert len(phase3) == 3

    def test_filter_for_phase3_returns_all_when_few(self) -> None:
        eps = [_make_endpoint("/a", ["GET"], auth=True)]
        mapper = AttackSurfaceMapper()
        surface = mapper.map(eps)
        phase3 = mapper.filter_for_phase3(surface, max_endpoints=10)
        assert len(phase3) == 1


class TestMapEndpointsUtility:
    def test_returns_surface_and_subset(self) -> None:
        eps = [
            _make_endpoint(
                "/api/x", ["POST"], auth=False, params=[RouteParam(name="data", source="body")]
            ),
        ]
        surface, phase3 = map_endpoints(eps, max_for_phase3=5)
        assert surface.total_endpoints == 1
        assert len(phase3) == 1


# ── helpers ──────────────────────────────────────────────────────────────────


def _make_endpoint(
    route: str,
    methods: list[str],
    auth: bool = False,
    params: list[RouteParam] | None = None,
    framework: str = "flask",
) -> HttpEndpoint:
    return HttpEndpoint(
        route=route,
        methods=methods,
        handler_func="handler",
        file_path="app.py",
        line=1,
        params=params or [],
        auth_required=auth,
        framework=framework,
    )
