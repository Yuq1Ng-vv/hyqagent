"""tests/eval — HyqAgent evaluation and regression tests.

Contains:
- ``test_golden_dataset.py`` — 28-case golden dataset regression (deterministic)
- ``test_ureport2_regression.py`` — Real-world Java/Spring project regression
- ``golden_loader.py`` — :class:`GoldenDatasetLoader` for querying golden cases
- ``conftest.py`` — Shared fixtures (Parser, TaintRuleLoader, golden dataset)

Future:
- LLM-based eval via DeepEval (Phase 5 Task 3)
- vulpy/dvna eval tests (real-world Python/JS projects)
"""
