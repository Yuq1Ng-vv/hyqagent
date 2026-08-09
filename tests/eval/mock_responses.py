"""tests/eval/mock_responses.py — Canned LLM tool_use responses for eval tests.

Each scenario returns a dict that matches what :meth:`AnthropicProvider.generate_structured`
returns: the ``input`` field of a tool_use content block.

Provides:
- 4 hypothesis-generation responses (matching HYPOTHESIS_SCHEMA)
- 3 validation responses (matching VALIDATOR_SCHEMA)
- A FakeProvider class that serves responses from a queue

All responses are deterministic — no real LLM is involved.
"""

from __future__ import annotations

from typing import Any

# ── HYPOTHESIS_SCHEMA responses ──────────────────────────────────────────────

SQLLI_TRUE_POSITIVE: dict[str, Any] = {
    "hypotheses": [
        {
            "vuln_type": "sql_injection",
            "cwe_id": "CWE-89",
            "title": "SQL Injection via unsanitized user input in query",
            "description": (
                "User-controlled input from request parameters flows into a raw "
                "SQL query string without parameterization. The query string is "
                "built via f-string interpolation and executed directly against "
                "the database."
            ),
            "severity": "high",
            "confidence": 0.92,
            "source_location": "fixture.py:12",
            "sink_location": "fixture.py:18",
            "reasoning": (
                "1. Source: request.args.get('q') reads unsanitized user input\n"
                "2. Data flow: input flows through variable 'query' without sanitization\n"
                "3. Sink: cursor.execute(query) executes raw SQL\n"
                "4. No parameterization or escaping is applied\n"
                "5. Attacker can inject arbitrary SQL via 'q' parameter"
            ),
            "remediation": (
                "Use parameterized queries with placeholders: "
                "cursor.execute('SELECT * FROM users WHERE name = ?', (q,))"
            ),
        }
    ]
}

XSS_TRUE_POSITIVE: dict[str, Any] = {
    "hypotheses": [
        {
            "vuln_type": "xss",
            "cwe_id": "CWE-79",
            "title": "Reflected XSS via unescaped user input in HTML response",
            "description": (
                "User input from query parameters is directly embedded into "
                "an HTML response without HTML entity encoding. An attacker "
                "can inject arbitrary JavaScript via the 'name' parameter."
            ),
            "severity": "medium",
            "confidence": 0.88,
            "source_location": "fixture.py:8",
            "sink_location": "fixture.py:14",
            "reasoning": (
                "1. Source: request.GET.get('name') reads user input\n"
                "2. Data flow: input flows to response without escaping\n"
                "3. Sink: HttpResponse(f'<h1>Hello {name}</h1>') embeds raw input\n"
                "4. No HTML encoding applied\n"
                "5. Attacker can inject <script>alert(1)</script> via 'name'"
            ),
            "remediation": (
                "Use Django's escape() or render the value inside a template "
                "with auto-escaping enabled."
            ),
        }
    ]
}

SSRF_TRUE_POSITIVE: dict[str, Any] = {
    "hypotheses": [
        {
            "vuln_type": "ssrf",
            "cwe_id": "CWE-918",
            "title": "Server-Side Request Forgery via user-controlled URL",
            "description": (
                "A user-supplied URL is passed directly to an HTTP client "
                "without validation. The server fetches the attacker-controlled "
                "URL, potentially accessing internal services."
            ),
            "severity": "high",
            "confidence": 0.85,
            "source_location": "fixture.py:10",
            "sink_location": "fixture.py:15",
            "reasoning": (
                "1. Source: request.form['url'] reads user-supplied URL\n"
                "2. Data flow: URL flows directly to HTTP client\n"
                "3. Sink: requests.get(user_url) fetches attacker-controlled URL\n"
                "4. No URL validation or allowlist\n"
                "5. Attacker can access internal metadata services (169.254.169.254)"
            ),
            "remediation": (
                "Validate the URL against an allowlist of permitted domains. "
                "Block access to internal IP ranges (10.0.0.0/8, 169.254.0.0/16, etc.)."
            ),
        }
    ]
}

EMPTY_HYPOTHESES: dict[str, Any] = {"hypotheses": []}


# ── VALIDATOR_SCHEMA responses ───────────────────────────────────────────────

VALIDATOR_CONFIRMED: dict[str, Any] = {
    "verdict": "confirmed",
    "confidence": 0.91,
    "q1_reachability": (
        "The source input (request.args.get('q')) is reachable at runtime — "
        "it is in an unprotected Flask route handler with no authentication "
        "guard. The value flows through a plain variable assignment into "
        "the SQL query sink with no conditional blocks in between."
    ),
    "q2_bypass": (
        "No conditions or guards exist between source and sink. The code "
        "path is a straight-line sequence of assignments leading directly "
        "to cursor.execute()."
    ),
    "q3_sanitizer": (
        "No sanitizer is present. The user input is used raw in an f-string "
        "that becomes the SQL query. No escaping, quoting, or whitelisting "
        "is applied."
    ),
    "q4_framework": (
        "The code uses raw sqlite3 cursor.execute() rather than an ORM. "
        "No framework-level SQL injection protection is active. Django ORM "
        "is not in use — this is bare Python DB-API."
    ),
    "q5_judgment": (
        "CONFIRMED: This is a real, exploitable SQL injection. An attacker "
        "can supply ' OR '1'='1 as the 'q' parameter to bypass "
        "authentication or extract arbitrary data via UNION SELECT."
    ),
    "exploit_scenario": (
        "GET /search?q='+UNION+SELECT+username,password+FROM+users-- "
        "would extract all user credentials."
    ),
}

VALIDATOR_REJECTED: dict[str, Any] = {
    "verdict": "rejected",
    "confidence": 0.94,
    "q1_reachability": (
        "The user input is read, but it flows into a parameterized query "
        "using '?' placeholders. The value is passed as the second argument "
        "to cursor.execute(), not interpolated into the SQL string."
    ),
    "q2_bypass": "N/A — the sink is safe regardless of input values.",
    "q3_sanitizer": (
        "The DB-API parameterization is the sanitizer. The driver separates "
        "the query structure from the data values, preventing any SQL "
        "injection regardless of input content."
    ),
    "q4_framework": (
        "Python's sqlite3 module provides built-in parameterization via "
        "cursor.execute(sql, params). This is sufficient protection — "
        "the query is pre-compiled with placeholders and data is bound "
        "separately."
    ),
    "q5_judgment": (
        "REJECTED: The code uses proper parameterized queries. The user "
        "input is passed as a data parameter, not interpolated into the "
        "SQL string. No SQL injection is possible."
    ),
    "exploit_scenario": "",
}

VALIDATOR_INCONCLUSIVE: dict[str, Any] = {
    "verdict": "inconclusive",
    "confidence": 0.55,
    "q1_reachability": (
        "The source endpoint is conditionally protected by an authentication "
        "middleware, but the middleware can be bypassed if the request "
        "includes a specific header. Cannot determine from static analysis "
        "whether this header is controllable."
    ),
    "q2_bypass": (
        "The auth middleware checks request.headers['X-Internal-Token'] "
        "against an environment variable. If this header is missing, the "
        "request is rejected — but the token value may be leaked or guessable."
    ),
    "q3_sanitizer": (
        "A custom sanitizer function strip_tags() is applied, but it only "
        "removes <script> tags and does not handle event handler attributes "
        "(onerror, onload) or javascript: URIs."
    ),
    "q4_framework": (
        "Express.js does not auto-escape HTML in res.send() — the developer "
        "must manually escape. No template engine with auto-escaping is used."
    ),
    "q5_judgment": (
        "INCONCLUSIVE: The auth bypass is plausible but not certain from "
        "static analysis alone. The sanitizer is weak but whether it can "
        "be exploited depends on the specific output context. Dynamic "
        "testing or manual review is recommended."
    ),
    "exploit_scenario": "",
}


# ── FakeProvider ────────────────────────────────────────────────────────────


class FakeProvider:
    """A fake provider that returns canned tool_use responses.

    Implements the same ``generate_structured()`` interface as
    :class:`hyqagent.models.providers.anthropic_provider.AnthropicProvider`
    so it can be injected into :class:`HypothesisGenerator` and
    :class:`Validator` without real LLM calls.

    Responses are served from a queue — each call consumes one response.
    Raises :class:`AssertionError` if more calls are made than responses queued.
    """

    def __init__(self, responses: list[dict[str, Any]] | None = None) -> None:
        self._queue: list[dict[str, Any]] = list(responses) if responses else []
        self._calls: list[dict[str, Any]] = []  # record of calls for assertions

    def enqueue(self, response: dict[str, Any]) -> None:
        """Add a response to the end of the queue."""
        self._queue.append(response)

    async def generate_structured(
        self,
        messages: list[dict[str, Any]],
        model: str = "",
        output_schema: dict[str, Any] | None = None,
        system: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> dict[str, Any]:
        """Return the next canned response from the queue.

        Records the call arguments for later assertion, then returns the
        next queued response.
        """
        self._calls.append(
            {
                "messages": messages,
                "model": model,
                "output_schema": output_schema,
                "system": system,
            }
        )
        if not self._queue:
            raise AssertionError(
                f"FakeProvider.generate_structured() called but queue is empty "
                f"(call #{len(self._calls)}). Enqueue more responses before the test."
            )
        return self._queue.pop(0)

    @property
    def call_count(self) -> int:
        """Number of times generate_structured() was called."""
        return len(self._calls)

    @property
    def last_call(self) -> dict[str, Any] | None:
        """The most recent call's arguments, or None."""
        return self._calls[-1] if self._calls else None


# ── Convenience helpers ─────────────────────────────────────────────────────

#: Pre-built provider that returns the SQLi true positive.
sqli_provider = FakeProvider([SQLLI_TRUE_POSITIVE])

#: Pre-built provider that returns no hypotheses (negative case).
empty_provider = FakeProvider([EMPTY_HYPOTHESES])

#: Pre-built provider that returns confirmed validation.
confirmed_provider = FakeProvider([VALIDATOR_CONFIRMED])

#: Pre-built provider that returns rejected validation.
rejected_provider = FakeProvider([VALIDATOR_REJECTED])
