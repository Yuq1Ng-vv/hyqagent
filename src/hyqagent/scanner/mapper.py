"""scanner/mapper.py — Attack surface mapping (Phase 2 of scan pipeline).

Consumes framework-extracted HTTP endpoints and produces a risk-prioritised
ranking that feeds Phase 3 hypothesis generation.  This is **pure-deterministic**
(zero LLM cost) — risk is scored from structural signals (HTTP method, parameter
count/source, auth posture, framework heuristics).

See DESIGN-IMPLEMENTATION.md §3.2 for the original specification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar

from hyqagent.cpg.frameworks.base import HttpEndpoint

# ── Enums ────────────────────────────────────────────────────────────────────


class EndpointCategory(StrEnum):
    """High-level risk category assigned to an endpoint."""

    AUTH_BYPASS = "auth_bypass"  # No auth — potential IDOR / privilege escalation
    DATA_MUTATION = "data_mutation"  # POST/PUT/PATCH/DELETE — state-changing
    FILE_UPLOAD = "file_upload"  # Multipart / file handling — RCE / traversal risk
    ADMIN_EXPOSED = "admin_exposed"  # Admin / management endpoints
    SENSITIVE_READ = "sensitive_read"  # GET that returns PII / tokens / secrets
    PUBLIC_READ = "public_read"  # GET with no auth, low sensitivity
    CONFIG_LEAK = "config_leak"  # Debug / actuator / info endpoints
    UNKNOWN = "unknown"


# ── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class ScoredEndpoint:
    """An :class:`HttpEndpoint` with a risk score and category."""

    endpoint: HttpEndpoint
    category: EndpointCategory
    risk_score: int  # 1-10 (1 = lowest risk, 10 = critical)
    reasons: list[str] = field(default_factory=list)

    @property
    def is_high_risk(self) -> bool:
        """Endpoints scoring ≥ 7 warrant Phase 3 LLM analysis."""
        return self.risk_score >= 7

    @property
    def is_medium_risk(self) -> bool:
        """Endpoints scoring 4-6 warrant medium-priority analysis."""
        return 4 <= self.risk_score <= 6


@dataclass
class AttackSurface:
    """Aggregated result of attack-surface mapping."""

    total_endpoints: int
    scored: list[ScoredEndpoint]
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0

    @property
    def high_risk(self) -> list[ScoredEndpoint]:
        """Return all endpoints with risk score ≥ 7."""
        return [s for s in self.scored if s.is_high_risk]

    @property
    def summary(self) -> dict[str, int]:
        """Label → count breakdown."""
        counts: dict[str, int] = {}
        for s in self.scored:
            counts[s.category.value] = counts.get(s.category.value, 0) + 1
        return counts


# ── Mapper ───────────────────────────────────────────────────────────────────


class AttackSurfaceMapper:
    """Deterministic endpoint risk scorer.

    Usage::

        mapper = AttackSurfaceMapper()
        surface = mapper.map(endpoints_from_frameworks)
        for ep in surface.high_risk:
            print(f"{ep.endpoint.route} → score={ep.risk_score} {ep.reasons}")
    """

    # ── Risk-weight tables ───────────────────────────────────────────────

    # Higher = riskier HTTP method
    _METHOD_WEIGHTS: ClassVar[dict[str, int]] = {
        "DELETE": 3,
        "PUT": 2,
        "PATCH": 2,
        "POST": 2,
        "GET": 0,
        "HEAD": 0,
        "OPTIONS": 0,
    }

    # Param source → risk contribution
    _PARAM_SOURCE_WEIGHTS: ClassVar[dict[str, int]] = {
        "body": 2,
        "file": 4,  # file upload → high risk
        "form": 1,
        "query": 1,
        "path": 0,
        "header": 0,
        "cookie": 0,
    }

    # Route patterns that suggest admin/management endpoints
    _ADMIN_PATTERNS: tuple[str, ...] = (
        "admin",
        "manage",
        "dashboard",
        "config",
        "setting",
        "actuator",
        "jmx",
        "console",
        "swagger",
        "api-doc",
        "graphql",
        "graphiql",
        "debug",
        "trace",
        "profile",
        "health",
        "info",
        "metrics",
        "env",
        "log",
        "backup",
        "restore",
        "import",
        "export",
        "register",
        "signup",
        "login",
        "signin",
        "auth",
        "oauth",
        "token",
        "reset",
        "password",
        "verify",
        "user",
        "account",
        "profile",
        "role",
        "permission",
    )

    # Route patterns suggesting file operations
    _FILE_PATTERNS: tuple[str, ...] = (
        "upload",
        "download",
        "file",
        "image",
        "photo",
        "avatar",
        "attachment",
        "media",
        "static",
        "backup",
        "export",
        "import",
        "report",
    )

    # ── Public API ───────────────────────────────────────────────────────

    def map(self, endpoints: list[HttpEndpoint]) -> AttackSurface:
        """Score and categorise every endpoint.

        Returns an :class:`AttackSurface` with endpoints ranked by risk.
        """
        scored: list[ScoredEndpoint] = []
        for ep in endpoints:
            s = self._score_one(ep)
            scored.append(s)

        # Sort high-to-low risk
        scored.sort(key=lambda s: s.risk_score, reverse=True)

        high = sum(1 for s in scored if s.is_high_risk)
        med = sum(1 for s in scored if s.is_medium_risk)
        low = len(scored) - high - med

        return AttackSurface(
            total_endpoints=len(endpoints),
            scored=scored,
            high_risk_count=high,
            medium_risk_count=med,
            low_risk_count=low,
        )

    def filter_for_phase3(
        self,
        surface: AttackSurface,
        max_endpoints: int = 50,
    ) -> list[ScoredEndpoint]:
        """Return the subset of endpoints that should feed Phase 3.

        Returns up to *max_endpoints* endpoints in descending risk order:
        high (≥7) first, then medium (4-6), then low (≤3) if budget remains.
        """
        result: list[ScoredEndpoint] = []

        for bucket in (
            [s for s in surface.scored if s.is_high_risk],
            [s for s in surface.scored if s.is_medium_risk],
            [s for s in surface.scored if not s.is_high_risk and not s.is_medium_risk],
        ):
            if len(result) >= max_endpoints:
                break
            result.extend(bucket[: max_endpoints - len(result)])

        return result

    # ── Scoring ──────────────────────────────────────────────────────────

    def _score_one(self, ep: HttpEndpoint) -> ScoredEndpoint:
        """Score a single endpoint 1-10."""
        reasons: list[str] = []
        score = 1  # base

        # --- Method risk ---
        method_score = self._score_method(ep)
        score += method_score
        if method_score >= 2:
            reasons.append(f"state-changing method ({','.join(ep.methods)})")

        # --- Parameter risk ---
        param_score = self._score_params(ep)
        score += param_score
        if param_score >= 2:
            reasons.append(f"{len(ep.params)} params with risky sources")

        # --- Auth posture ---
        auth_penalty = self._score_auth(ep)
        score += auth_penalty
        if auth_penalty > 0:
            reasons.append("no authentication required")

        # --- Route heuristics ---
        route_score = self._score_route(ep)
        score += route_score

        # --- Category determination ---
        category = self._categorise(ep, reasons)

        return ScoredEndpoint(
            endpoint=ep,
            category=category,
            risk_score=min(10, max(1, score)),
            reasons=reasons,
        )

    def _score_method(self, ep: HttpEndpoint) -> int:
        """Score based on HTTP method risk."""
        if not ep.methods:
            return 1  # unknown → assume risky
        return max(self._METHOD_WEIGHTS.get(m.upper(), 1) for m in ep.methods)

    def _score_params(self, ep: HttpEndpoint) -> int:
        """Score based on parameter count and sources."""
        score = 0
        for p in ep.params:
            score += self._PARAM_SOURCE_WEIGHTS.get(p.source, 0)
        # Cap parameter contribution
        return min(4, score)

    def _score_auth(self, ep: HttpEndpoint) -> int:
        """Penalty for missing auth; bonus for auth present."""
        if ep.auth_required:
            return -1  # slight risk reduction
        # No auth on a state-changing endpoint is worse
        if any(m.upper() in ("POST", "PUT", "PATCH", "DELETE") for m in ep.methods):
            return 3
        return 1

    def _score_route(self, ep: HttpEndpoint) -> int:
        """Score based on route path heuristics."""
        route_lower = ep.route.lower()
        score = 0

        for pat in self._ADMIN_PATTERNS:
            if pat in route_lower:
                score += 2
                break  # only count once

        for pat in self._FILE_PATTERNS:
            if pat in route_lower:
                score += 3
                break

        return min(5, score)

    # ── Categorisation ───────────────────────────────────────────────────

    def _categorise(
        self,
        ep: HttpEndpoint,
        reasons: list[str],
    ) -> EndpointCategory:
        """Assign a risk category based on accumulated signals."""
        route_lower = ep.route.lower()

        # File upload
        if any(p.source == "file" for p in ep.params) or any(
            pat in route_lower for pat in ("upload", "file", "image", "avatar", "attachment")
        ):
            reasons.append("file upload / file operation endpoint")
            return EndpointCategory.FILE_UPLOAD

        # Admin / config
        if any(
            pat in route_lower
            for pat in (
                "admin",
                "manage",
                "dashboard",
                "config",
                "setting",
                "actuator",
                "jmx",
                "console",
                "swagger",
                "api-doc",
            )
        ):
            reasons.append("admin or management endpoint")
            return EndpointCategory.ADMIN_EXPOSED

        # Debug / config leak
        if any(
            pat in route_lower
            for pat in ("debug", "trace", "health", "info", "metrics", "env", "graphql", "graphiql")
        ):
            reasons.append("debug or infrastructure endpoint — potential config leak")
            return EndpointCategory.CONFIG_LEAK

        # Auth-related but no auth guard
        if (
            any(
                pat in route_lower
                for pat in (
                    "login",
                    "signin",
                    "register",
                    "signup",
                    "token",
                    "reset",
                    "password",
                    "oauth",
                    "verify",
                )
            )
            and not ep.auth_required
        ):
            reasons.append("auth endpoint without detected auth guard")
            return EndpointCategory.AUTH_BYPASS

        # Data mutation without auth
        stateful = any(m.upper() in ("POST", "PUT", "PATCH", "DELETE") for m in ep.methods)
        if stateful and not ep.auth_required:
            reasons.append("state-changing endpoint without authentication")
            return EndpointCategory.AUTH_BYPASS

        if stateful:
            return EndpointCategory.DATA_MUTATION

        # Default: GET without auth
        if not ep.auth_required:
            return EndpointCategory.PUBLIC_READ

        return EndpointCategory.UNKNOWN


# ── Utility ──────────────────────────────────────────────────────────────────


def map_endpoints(
    endpoints: list[HttpEndpoint],
    max_for_phase3: int = 50,
) -> tuple[AttackSurface, list[ScoredEndpoint]]:
    """Map *endpoints* and return ``(full_surface, phase3_subset)``."""
    mapper = AttackSurfaceMapper()
    surface = mapper.map(endpoints)
    phase3 = mapper.filter_for_phase3(surface, max_endpoints=max_for_phase3)
    return surface, phase3
