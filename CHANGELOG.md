# Changelog

All notable changes to HyqAgent are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-09

### Phase 5: Quality & Release (in progress)

#### Added (Session 1.35)
- LLM Eval (DeepEval): 4 custom deterministic metrics (VulnTypeAccuracy, SeverityAgreement, CWEMapping, VerdictCorrectness)
- Mock Pipeline tests: 166 pass, 15 skip — HypothesisGenerator + Validator L1/L2
- FakeProvider for zero-cost eval testing
- Opt-in real LLM eval via `HYQAGENT_EVAL_REAL_LLM=1`

#### Added (Session 1.34)
- Scanner-level Golden integration tests: 5 test methods, 140 parametrized cases (L5)
- CPG infrastructure fixes: taint label expansion, source/sink role separation, CSRF rule
- Golden tests total: 375 pass, 129 skip (L1-L5)

#### Added (Session 1.33)
- Golden Dataset v1: 28 labeled vulnerability cases (14 reuse + 13 gap-fill + 1 negative)
- 4-level deterministic regression tests (fixture → CPG → taint → negative)
- 14 new fixture files (XSS/SSRF/OpenRedirect/Crypto/CSRF/AuthBypass × 3 languages)
- 364 eval test items, zero LLM/API need, ~0.8s runtime

### Phase 4: Long-Running Agent

#### Added (Session 1.32)
- Dual-mode LLM audit strategy: `--mode precision` (fast) vs `--mode recall` (thorough)
- AgentLoop ReAct: multi-turn code exploration with 5 BaseTool code tools
- ToolRegistry: tool registration/execution/formatting
- Dynamic validation sandbox: Docker PoC execution (L6 verification)
- Fixed systemic code blindness: 3 LLM channels receiving empty code_context

#### Added (Session 1.31)
- Report CLI integration: `generate()` with 8 deep-audit parameters
- JSON report: 5 deep sections (hypotheses/validations/convergence/cost/deep_audit)
- Markdown report: 4 deep chapters (LLM假设/收敛/成本/执行阶段)
- `resume` command: `--format`/`--output` options
- Web vulnerability coverage analysis: 200-item matrix, top blind spots identified

#### Added (Session 1.30)
- Java annotation extraction: `extract_decorators()` via tree-sitter
- JAX-RS framework extractor (~250 lines)
- Spring extractor deepening: controller validation, @FeignClient, Actuator endpoints
- Java config scanner (~380 lines): pom.xml + properties/yml + web.xml
- 5 new Java vulnerability fixtures (deser/jndi/spel/xxe/ssti)

#### Added (Session 1.29)
- ObservabilityManager: span tracing across audit phases
- PrometheusMetrics: 6 core metrics
- AuditTrail: SHA-256 hash chain for tamper-proof audit records
- Provider observer callbacks: CostTracker receives real data

#### Added (Session 1.28)
- Convergence loop completion: 4 phases (ADVERSARIAL_REVIEW/SATURATION_SCAN/REVERSE_SINK/BLIND_SCAN) now re-run each iteration

#### Added (Session 1.27)
- Closed-loop seed feedback: P0 — findings from 3 channels feed back into hypothesis generation
- `generate_from_seeds()` + `_read_function_source()` in HypothesisGenerator

#### Added (Session 1.26)
- Reverse Sink analysis (Channel 3, zero-LLM): trace from sinks back to entry points
- Blind Scan (Channel 2, LLM): coverage for patterns missed by deterministic scanner
- Orchestrator integration: 2 new phases + convergence perspective linkage

#### Added (Session 1.25)
- SaturationScanner: iterative same-class vulnerability discovery until convergence

#### Added (Session 1.24)
- AdversarialReviewer: adversarial review of findings (~365 lines)

#### Added (Session 1.23)
- Orchestrator: convergence loop orchestration + checkpoint resume
- 5-dimension convergence metrics: VDR, EC, RWC, VCC, C_hat
- CLI `resume` command: real implementation replacing stub

### Phase 3: LLM Integration

#### Added (Session 1.22)
- Python/JS taint rules expansion to 12 categories
- memory/ context management package: 3-zone model + crystallization + hybrid retrieval

#### Added (Session 1.21)
- AutoCVE横向对比研究 → `docs/AUTOCVE-RESEARCH.md`
- Nudge system (~380 lines): 3 Nudge types + 3 built-in StopHooks
- HypothesisGenerator + Validator NudgeLoop integration

#### Added (Session 1.20)
- AttackSurfaceMapper: endpoint classification + risk scoring
- Session management: SQLite schema + SessionManager + BeliefSystem + CheckpointManager
- Bayesian belief update with 7 EvidenceStrength presets

#### Added (Session 1.18-1.19)
- Anthropic Provider: DeepSeek + Claude dual base_url support
- Model Router: CHEAP/MID/STRONG 3-tier routing + complexity assessment
- HypothesisGenerator: CPG slice → LLM structured hypothesis generation
- Validator: L1 deterministic + L2 LLM 5-question validation
- CostTracker: per-phase cost attribution + budget control
- Coverage Auditor: zero-LLM differential coverage analysis
- CompletenessCritic

### Phase 2: Deterministic Scanner

#### Added (Sessions 1.14-1.17)
- DeterministicScanner: 5-phase scanning pipeline
- PathAnnotator: 10 label classification (PathLabel)
- SinkDiscoverer + SourceCompletenessChecker
- CoverageTracker: ~179 blind spot detection
- CoverageMetrics: metric aggregation

### Phase 1: CPG Foundation

#### Added (Sessions 1.1-1.16)
- Multi-language CPG Engine: Python/JavaScript/Java
- tree-sitter parser + AST traverser
- LanguageProvider strategy pattern: add language = 1 file + 1 line
- SingleFileCallGraph + CrossFileCallGraphBuilder
- DataFlowBuilder: def-use chains + cross-function taint tracking
- CPGGraphBuilder: NetworkX MultiDiGraph with pickle cache (~2700x speedup)
- CPGQuery: find_path/find_sources/find_sinks/get_call_chain/slice_path
- Taint rules: 3 languages × 10 categories (YAML)
- 6 Framework extractors: Flask/Django/FastAPI/Express/Spring/JAX-RS
- ureport2 validation: 469 Java files, 76K nodes/240K edges
- 26 bugs found and fixed during adversarial review

[0.1.0]: https://github.com/hyqagent/hyqagent/releases/tag/v0.1.0
