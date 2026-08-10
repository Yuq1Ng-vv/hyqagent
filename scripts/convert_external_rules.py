#!/usr/bin/env python3
"""convert_external_rules.py — One-shot script: import Semgrep + Find-Sec-Bugs
rules into HyqAgent's taint_rules.yaml format.

Usage:  uv run python scripts/convert_external_rules.py

Sources:
  /tmp/semgrep-rules/     — 1000+ semgrep community rules
  /tmp/find-sec-bugs/     — 800+ Java API sink signatures
Output:
  src/hyqagent/cpg/taint_rules.yaml  (updated in-place, original preserved as .bak)
"""

from __future__ import annotations

import re
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

# ── Paths ───────────────────────────────────────────────────────────────────
HYQAGENT_ROOT = Path(__file__).resolve().parents[1]
TAINT_RULES_PATH = HYQAGENT_ROOT / "src" / "hyqagent" / "cpg" / "taint_rules.yaml"
SEMGREP_RULES_DIR = Path("/tmp/semgrep-rules")
FINDSECBUGS_DIR = Path("/tmp/find-sec-bugs")
FINDSECBUGS_SINKS_DIR = (
    FINDSECBUGS_DIR
    / "findsecbugs-plugin"
    / "src"
    / "main"
    / "resources"
    / "injection-sinks"
)

# ── CWE to vuln_type mapping ───────────────────────────────────────────────
CWE_TO_VULN: dict[str, str] = {
    "CWE-89": "sql_injection",
    "CWE-564": "sql_injection",
    "CWE-943": "sql_injection",  # NoSQL injection
    "CWE-78": "command_injection",
    "CWE-77": "command_injection",
    "CWE-79": "xss",
    "CWE-80": "xss",
    "CWE-83": "xss",
    "CWE-84": "xss",
    "CWE-87": "xss",
    "CWE-918": "ssrf",
    "CWE-441": "ssrf",
    "CWE-22": "path_traversal",
    "CWE-23": "path_traversal",
    "CWE-35": "path_traversal",
    "CWE-36": "path_traversal",
    "CWE-502": "deserialization",
    "CWE-470": "deserialization",
    "CWE-601": "open_redirect",
    "CWE-698": "open_redirect",
    "CWE-94": "code_injection",
    "CWE-95": "code_injection",
    "CWE-1336": "ssti",
    "CWE-611": "xxe",
    "CWE-827": "xxe",
    "CWE-327": "crypto_weakness",
    "CWE-328": "crypto_weakness",
    "CWE-916": "crypto_weakness",
    "CWE-287": "auth_bypass",
    "CWE-306": "auth_bypass",
    "CWE-384": "auth_bypass",
    "CWE-862": "auth_bypass",
    "CWE-863": "auth_bypass",
    "CWE-639": "idor",
    "CWE-352": "csrf",
    "CWE-200": "info_disclosure",
    "CWE-209": "info_disclosure",
    "CWE-532": "info_disclosure",
    "CWE-798": "hardcoded_secret",
    "CWE-259": "hardcoded_secret",
    "CWE-400": "dos",
    "CWE-770": "dos",
    "CWE-776": "dos",  # billion laughs
    "CWE-434": "file_upload",
    "CWE-732": "permission_issue",
    "CWE-269": "permission_issue",
    "CWE-284": "access_control",
    "CWE-285": "access_control",
    "CWE-749": "access_control",
    "CWE-362": "race_condition",
    "CWE-367": "race_condition",
    "CWE-338": "weak_random",
    "CWE-330": "weak_random",
    "CWE-319": "cleartext_transmission",
    "CWE-311": "cleartext_transmission",
    "CWE-915": "nosql_injection",
    "CWE-917": "injection_general",
    "CWE-74": "injection_general",
    "CWE-73": "path_traversal",
    "CWE-90": "ldap_injection",
    "CWE-91": "xpath_injection",
    "CWE-643": "xpath_injection",
    "CWE-99": "injection_general",
    "CWE-113": "header_injection",
    "CWE-644": "header_injection",
    "CWE-93": "crlf_injection",
    "CWE-117": "log_injection",
    "CWE-134": "format_string",
    "CWE-190": "integer_overflow",
    "CWE-191": "integer_underflow",
    "CWE-787": "buffer_overflow",
    "CWE-125": "buffer_overflow",
    "CWE-416": "use_after_free",
    "CWE-476": "null_pointer",
    "CWE-415": "double_free",
}

# ── Find-Sec-Bugs filename → vuln_type ─────────────────────────────────────
FSB_VULN_MAP: dict[str, str] = {
    "sql": "sql_injection",
    "command": "command_injection",
    "command-scala": "command_injection",
    "urlconnection-ssrf": "ssrf",
    "scala-play-ssrf": "ssrf",
    "xss-servlet": "xss",
    "xss-jsp": "xss",
    "xss-scala-twirl": "xss",
    "xss-scala-mvc-api": "xss",
    "path-traversal-in": "path_traversal",
    "path-traversal-out": "path_traversal",
    "kotlin-path-traversal-in": "path_traversal",
    "scala-path-traversal-in": "path_traversal",
    "scala-path-traversal-out": "path_traversal",
    "script-engine": "code_injection",
    "spel": "ssti",
    "el": "ssti",
    "seam-el": "ssti",
    "xpath-apache": "xpath_injection",
    "xpath-javax": "xpath_injection",
    "ldap": "ldap_injection",
    "xslt": "xxe",
    "crlf-logs": "log_injection",
    "response-splitting": "header_injection",
    "http-parameter-pollution": "injection_general",
    "smtp": "header_injection",
    "formatter": "format_string",
    "trust-boundary-violation-attribute": "info_disclosure",
    "trust-boundary-violation-value": "info_disclosure",
    "sensitive-data-exposure-scala": "info_disclosure",
    "spring-file-disclosure": "path_traversal",
    "struts-file-disclosure": "path_traversal",
    "requestdispatcher-file-disclosure": "path_traversal",
    "beans": "code_injection",
    "aws": "injection_general",
    "struts2": "injection_general",
}

# ── HyqAgent-supported languages ────────────────────────────────────────────
HYQAGENT_LANGS = {"python", "javascript", "java"}

# Semgrep language name → HyqAgent language name
SEMGREP_LANG_MAP: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "java": "java",
}


def _cwe_to_vuln_type(cwe_str: str) -> str | None:
    """Extract CWE ID from string like 'CWE-89: ...' and map to vuln_type."""
    if not cwe_str:
        return None
    cwe_id = cwe_str.split(":")[0].strip()
    return CWE_TO_VULN.get(cwe_id)


# ── Step 1: Extract Semgrep taint patterns ─────────────────────────────────

SEMGREP_STATS: dict[str, int] = defaultdict(int)


def _extract_pattern_strings(
    node: Any, language: str
) -> set[str]:
    """Recursively extract pattern strings from a semgrep pattern tree.

    Semgrep patterns can be nested: patterns, pattern-either, pattern,
    pattern-inside, pattern-not-inside, etc.  We only care about
    pattern/pattern-either/patterns that describe source or sink code.

    Filters:
    - Skip metavariable-only patterns (e.g. ``$F(...)`` — too generic)
    - Skip overly short patterns (< 6 chars)
    - Resolve language aliases
    - Remove leading/trailing wildcards (``...``)
    """
    results: set[str] = set()

    if isinstance(node, str):
        # Strip trailing '...' (match rest) but keep leading context
        # Resolve language aliases for typescript → javascript
        cleaned = node.strip()
        if cleaned.startswith("..."):
            cleaned = cleaned[3:].strip()
        if cleaned.endswith("..."):
            cleaned = cleaned[:-3].strip()
        if len(cleaned) >= 6 and not cleaned.startswith("$"):
            if not _is_overly_generic(cleaned, language):
                results.add(cleaned)
        return results

    if isinstance(node, dict):
        for pattern_key in ("pattern", "pattern-not", "pattern-inside"):
            if pattern_key in node:
                results.update(
                    _extract_pattern_strings(node[pattern_key], language)
                )

        for list_key in (
            "patterns",
            "pattern-either",
            "pattern-not-inside",
        ):
            if list_key in node:
                for item in node[list_key]:
                    results.update(_extract_pattern_strings(item, language))

        # Handle pattern-regex (convert to keyword pattern)
        if "pattern-regex" in node:
            regex = node["pattern-regex"]
            # Simple regex: extract the constant part
            if regex and not regex.startswith("(?") and not regex.startswith("^"):
                parts = regex.split("|")
                for part in parts:
                    clean = re.sub(r"[.*+?^${}()|[\]\\]", "", part)
                    if len(clean) >= 6:
                        results.add(clean)

    if isinstance(node, list):
        for item in node:
            results.update(_extract_pattern_strings(item, language))

    return results


def _is_overly_generic(pattern: str, language: str) -> bool:
    """Filter out patterns that would produce too many false positives."""
    too_generic = [
        # Generic variable patterns
        "request.",
        "request[",
        "response.",
        "session.",
        "user.",
        "input",
        "params",
        "param[",
        "query[",
        "data[",
        "body[",
        # Overly short
        "get(",
        "post(",
        "put(",
        "exec(",
        "eval(",
        "run(",
        # Language-specific generic
    ]
    for g in too_generic:
        if g in pattern.lower():
            return True
    return False


def extract_semgrep_rules() -> dict[str, dict[str, dict[str, set[str]]]]:
    """Parse semgrep-rules and return {lang: {sources|sinks: {vuln: {patterns}}}}"""
    result: dict[str, dict[str, dict[str, set[str]]]] = {}
    for lang in HYQAGENT_LANGS:
        result[lang] = {"sources": defaultdict(set), "sinks": defaultdict(set)}

    # Find taint-mode rules
    taint_files: list[Path] = []
    for lang_dir in ["python", "javascript", "java"]:
        lang_path = SEMGREP_RULES_DIR / lang_dir
        if lang_path.exists():
            for yf in lang_path.rglob("*.yaml"):
                try:
                    content = yf.read_text(encoding="utf-8")
                    if "mode: taint" in content:
                        taint_files.append(yf)
                except Exception:
                    continue

    print(f"  Found {len(taint_files)} taint-mode rule files from semgrep-rules")

    for yf in taint_files:
        try:
            rules_doc = yaml.safe_load(yf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not rules_doc:
            continue
        rules = rules_doc.get("rules", [])
        if not isinstance(rules, list):
            continue

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("mode") != "taint":
                continue

            # ── Resolve language ──
            languages = rule.get("languages", [])
            if isinstance(languages, str):
                languages = [languages]
            hyq_langs: set[str] = set()
            for l in languages:
                mapped = SEMGREP_LANG_MAP.get(l)
                if mapped:
                    hyq_langs.add(mapped)

            # ── Resolve vuln_type from CWE ──
            cwe_list = rule.get("metadata", {}).get("cwe", [])
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]
            vuln_types: set[str] = set()
            for cwe_entry in cwe_list:
                vt = _cwe_to_vuln_type(cwe_entry)
                if vt:
                    vuln_types.add(vt)
            if not vuln_types:
                # Try from rule id or message keywords
                rid = rule.get("id", "")
                msg = str(rule.get("message", ""))
                combined = f"{rid} {msg}".lower()
                if "sql" in combined:
                    vuln_types.add("sql_injection")
                elif "command" in combined or "subprocess" in combined:
                    vuln_types.add("command_injection")
                elif "xss" in combined or "cross-site" in combined:
                    vuln_types.add("xss")
                elif "ssrf" in combined:
                    vuln_types.add("ssrf")
                elif "path" in combined and "traversal" in combined:
                    vuln_types.add("path_traversal")
                elif "deserializ" in combined:
                    vuln_types.add("deserialization")
                elif "redirect" in combined:
                    vuln_types.add("open_redirect")
                elif "csrf" in combined:
                    vuln_types.add("csrf")
                else:
                    continue  # skip if we can't classify

            # ── Extract sources ──
            src_patterns: set[str] = set()
            for lang in hyq_langs:
                for src_block in rule.get("pattern-sources", []):
                    src_patterns.update(_extract_pattern_strings(src_block, lang))

            # ── Extract sinks ──
            sink_patterns: set[str] = set()
            for lang in hyq_langs:
                for snk_block in rule.get("pattern-sinks", []):
                    sink_patterns.update(_extract_pattern_strings(snk_block, lang))

            if not src_patterns and not sink_patterns:
                continue

            for lang in hyq_langs:
                for vt in vuln_types:
                    if src_patterns:
                        result[lang]["sources"][vt].update(src_patterns)
                        SEMGREP_STATS[f"{lang}:sources:{vt}"] += len(src_patterns)
                    if sink_patterns:
                        result[lang]["sinks"][vt].update(sink_patterns)
                        SEMGREP_STATS[f"{lang}:sinks:{vt}"] += len(sink_patterns)

    return result


# ── Step 2: Extract Find-Sec-Bugs Java sinks ───────────────────────────────


def _fsb_line_to_pattern(line: str) -> str | None:
    """Convert a Find-Sec-Bugs signature line to a HyqAgent sink pattern.

    Find-Sec-Bugs uses JVM bytecode signatures:
      java/sql/Statement.executeQuery(Ljava/lang/String;)Ljava/sql/ResultSet;:0

    The trailing ``:0`` is the tainted parameter index (0-based).

    We extract the full class.method part as a pattern that can be matched
    against AST node source text at the CPG level.
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None

    # Remove trailing :param_index
    param_idx = "0"
    if re.search(r":\d+$", line):
        parts = line.rsplit(":", 1)
        param_idx = parts[1]
        line = parts[0]

    # Skip if the tainted param is not index 0 or 1 (too indirect)
    # 0 = the main query argument, 1 = second arg (often still the query)

    # Extract the JVM internal name: java/sql/Statement.executeQuery(...)
    # Convert to: Statement.executeQuery
    # Keep entire class.method for matching at CPG node level
    last_slash = line.rfind("/")
    if last_slash >= 0:
        class_part = line[:last_slash].replace("/", ".")
        method_part = line[last_slash + 1:]
    else:
        class_part = ""
        method_part = line

    if "(" in method_part:
        method_name = method_part[: method_part.index("(")]

        # Case 1: ClassName.methodName (e.g. java.sql.Statement.executeQuery)
        # → pattern: 'Statement.executeQuery(' (without package prefix)
        simple_class = class_part.split(".")[-1] if class_part else ""
        if simple_class and method_name:
            return f"{simple_class}.{method_name}("

        # Case 2: methodName only (fallback)
        if method_name and len(method_name) >= 4:
            return method_name + "("

    # Bare method name
    if method_part:
        bare_name = method_part.rstrip(";")
        if len(bare_name) >= 4:
            return bare_name + "("

    return None


def extract_findsecbugs_sinks() -> dict[str, set[str]]:
    """Parse Find-Sec-Bugs sink files → {vuln_type: {java patterns}}"""
    result: dict[str, set[str]] = defaultdict(set)

    if not FINDSECBUGS_SINKS_DIR.exists():
        print("  WARNING: Find-Sec-Bugs sink directory not found — skipping")
        return result

    sink_files = list(FINDSECBUGS_SINKS_DIR.glob("*.txt"))
    print(f"  Found {len(sink_files)} sink files from find-sec-bugs")

    for sf in sink_files:
        basename = sf.stem  # e.g. "sql-jdbc", "command", "xss-servlet"

        # Map to vuln_type
        vuln_type = None
        for key, vt in FSB_VULN_MAP.items():
            if basename.startswith(key) or key in basename:
                vuln_type = vt
                break
        if vuln_type is None:
            # Try prefix matching
            prefix = basename.split("-")[0]
            vuln_type = FSB_VULN_MAP.get(prefix)
        if vuln_type is None:
            continue

        count = 0
        for line in sf.read_text(encoding="utf-8").splitlines():
            pattern = _fsb_line_to_pattern(line)
            if pattern and len(pattern) >= 4:
                result[vuln_type].add(pattern)
                count += 1

        if count:
            print(f"    {basename}: {count} patterns → {vuln_type}")

    return result


# ── Step 4: Deduplication & Validation ─────────────────────────────────────


def merge_and_dedup(
    original: dict[str, Any],
    semgrep_data: dict[str, dict[str, dict[str, set[str]]]],
    fsb_java_sinks: dict[str, set[str]],
) -> dict[str, Any]:
    """Merge extracted patterns into the original taint_rules.yaml structure.

    Deduplication rules:
    - Skip patterns already present in the original
    - Skip patterns that are too short (< 4 chars)
    - Skip patterns that conflict with sanitizer patterns
    """
    merged = deepcopy(original)
    stats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for lang in HYQAGENT_LANGS:
        if lang not in merged:
            merged[lang] = {"sources": {}, "sinks": {}, "sanitizers": {}}

        # ── Ensure all vuln_type keys exist ──
        for section in ("sources", "sinks"):
            if section not in merged[lang]:
                merged[lang][section] = {}
            if not isinstance(merged[lang][section], dict):
                merged[lang][section] = {}

        # ── Merge semgrep sources ──
        for vt, patterns in semgrep_data.get(lang, {}).get("sources", {}).items():
            if vt not in merged[lang]["sources"]:
                merged[lang]["sources"][vt] = []
            existing = set(merged[lang]["sources"][vt])
            for pat in patterns:
                pat_clean = pat.strip()
                if pat_clean and pat_clean not in existing and len(pat_clean) >= 4:
                    merged[lang]["sources"][vt].append(pat_clean)
                    existing.add(pat_clean)
                    stats[lang]["sources_added"] += 1

        # ── Merge semgrep sinks ──
        for vt, patterns in semgrep_data.get(lang, {}).get("sinks", {}).items():
            if vt not in merged[lang]["sinks"]:
                merged[lang]["sinks"][vt] = []
            existing = set(merged[lang]["sinks"][vt])
            for pat in patterns:
                pat_clean = pat.strip()
                if pat_clean and pat_clean not in existing and len(pat_clean) >= 4:
                    merged[lang]["sinks"][vt].append(pat_clean)
                    existing.add(pat_clean)
                    stats[lang]["sinks_added"] += 1

        # ── Merge Find-Sec-Bugs Java sinks ──
        if lang == "java":
            for vt, patterns in fsb_java_sinks.items():
                if vt not in merged[lang]["sinks"]:
                    merged[lang]["sinks"][vt] = []
                existing = set(merged[lang]["sinks"][vt])
                for pat in patterns:
                    pat_clean = pat.strip()
                    if pat_clean and pat_clean not in existing and len(pat_clean) >= 4:
                        merged[lang]["sinks"][vt].append(pat_clean)
                        existing.add(pat_clean)
                        stats[lang]["fsb_sinks_added"] += 1

        # ── Ensure sanitizers section exists ──
        if "sanitizers" not in merged[lang]:
            merged[lang]["sanitizers"] = {}

    return merged, dict(stats)


def validate(original: dict[str, Any], merged: dict[str, Any]) -> bool:
    """Validate merged rules: no duplicates, no empty categories, valid YAML."""
    errors: list[str] = []

    for lang in HYQAGENT_LANGS:
        if lang not in merged:
            errors.append(f"Missing language section: {lang}")
            continue

        for section in ("sources", "sinks"):
            if section not in merged[lang]:
                errors.append(f"Missing {section} section in {lang}")
                continue
            for vt, patterns in list(merged[lang][section].items()):
                if not isinstance(patterns, list):
                    errors.append(f"{lang}.{section}.{vt}: not a list")
                    continue
                if not patterns:
                    # Remove empty categories
                    del merged[lang][section][vt]
                    print(f"    ⚠️  Removed empty: {lang}.{section}.{vt}")
                    continue
                # Check for duplicates and remove them
                seen: set[str] = set()
                deduped: list[str] = []
                dupes = 0
                for p in patterns:
                    if p not in seen:
                        seen.add(p)
                        deduped.append(p)
                    else:
                        dupes += 1
                if dupes:
                    merged[lang][section][vt] = deduped
                    print(f"    ⚠️  {lang}.{section}.{vt}: removed {dupes} duplicates")

        # Check sanitizers
        sanitizers = merged[lang].get("sanitizers", {})
        for vt, patterns in sanitizers.items():
            # Sanitizers must not overlap with sources/sinks of same vuln type
            src_patterns = set(merged[lang].get("sources", {}).get(vt, []))
            snk_patterns = set(merged[lang].get("sinks", {}).get(vt, []))
            san_set = set(patterns)
            overlap_src = san_set & src_patterns
            overlap_snk = san_set & snk_patterns
            if overlap_src:
                print(
                    f"    ⚠️  {lang}.sanitizers.{vt}: {len(overlap_src)} patterns "
                    f"also appear in sources (pre-existing, skipping for safety)"
                )
                # Remove overlapping patterns from sanitizers
                merged[lang]["sanitizers"][vt] = list(san_set - src_patterns - snk_patterns)
            if overlap_snk:
                print(
                    f"    ⚠️  {lang}.sanitizers.{vt}: {len(overlap_snk)} patterns "
                    f"also appear in sinks (pre-existing, removing to avoid false negatives)"
                )
                merged[lang]["sanitizers"][vt] = list(
                    set(merged[lang]["sanitizers"].get(vt, [])) - snk_patterns
                )

    if errors:
        print("\n  ❌ VALIDATION ERRORS:")
        for e in errors[:20]:
            print(f"    - {e}")
        return False

    # Count stats
    for lang in HYQAGENT_LANGS:
        for section in ("sources", "sinks"):
            total = sum(
                len(v) for v in merged[lang].get(section, {}).values()
                if isinstance(v, list)
            )
            orig_total = sum(
                len(v) for v in original.get(lang, {}).get(section, {}).values()
                if isinstance(v, list)
            )
            print(f"  {lang:>12} {section:>10}: {orig_total:>5} → {total:>5} patterns")

    return True


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> None:
    print("=" * 60)
    print("HyqAgent External Rule Importer")
    print("=" * 60)

    # Load original
    if not TAINT_RULES_PATH.exists():
        print(f"ERROR: taint_rules.yaml not found at {TAINT_RULES_PATH}")
        return

    original = yaml.safe_load(TAINT_RULES_PATH.read_text(encoding="utf-8"))
    print(f"\nLoaded original: {TAINT_RULES_PATH}")
    print(f"  Languages: {[k for k in original if k in HYQAGENT_LANGS]}")

    # Step 1: Semgrep rules
    print("\n── Step 1: Extracting Semgrep taint rules ──")
    semgrep_data = extract_semgrep_rules()
    for lang in HYQAGENT_LANGS:
        src_count = sum(
            len(v)
            for v in semgrep_data.get(lang, {}).get("sources", {}).values()
        )
        snk_count = sum(
            len(v) for v in semgrep_data.get(lang, {}).get("sinks", {}).values()
        )
        print(f"  {lang}: {src_count} source patterns, {snk_count} sink patterns")

    # Step 2: Find-Sec-Bugs Java sinks
    print("\n── Step 2: Extracting Find-Sec-Bugs Java sinks ──")
    fsb_sinks = extract_findsecbugs_sinks()
    fsb_total = sum(len(v) for v in fsb_sinks.values())
    print(f"  Total: {fsb_total} Java sink patterns across {len(fsb_sinks)} categories")

    # Step 3: Merge and deduplicate
    print("\n── Step 4: Merging & deduplicating ──")
    merged, stats = merge_and_dedup(original, semgrep_data, fsb_sinks)

    # ── Post-processing: ensure every sink category has source patterns ──
    print("\n── Post-processing: Backfilling source/sink patterns for new categories ──")
    for lang in HYQAGENT_LANGS:
        if lang not in merged:
            continue
        sources = merged[lang].get("sources", {})
        sinks = merged[lang].get("sinks", {})

        # Generic source sets to inherit from (ordered by specificity)
        parent_categories = [
            "sql_injection",
            "command_injection",
            "injection_general",
        ]
        for sink_cat in sinks:
            if sink_cat not in sources or not sources[sink_cat]:
                # Find a parent category that has sources
                for parent in parent_categories:
                    if parent in sources and sources[parent]:
                        merged[lang]["sources"][sink_cat] = list(sources[parent])  # shallow copy
                        print(
                            f"  {lang}.sources.{sink_cat}: "
                            f"inherited {len(sources[parent])} patterns from {parent}"
                        )
                        stats.setdefault(lang, {}).setdefault("inherited_sources", 0)
                        stats[lang]["inherited_sources"] += len(sources[parent])
                        break

        # ── Reverse: categories with sources but no sinks ──
        # (e.g., nosql_injection should inherit from sql_injection sinks)
        sink_parents: dict[str, str] = {
            "nosql_injection": "sql_injection",
            "xpath_injection": "sql_injection",  # XPath injection sinks are similar
            "injection_general": "sql_injection",
            "info_disclosure": "command_injection",
            "format_string": "command_injection",
            "log_injection": "command_injection",
            "header_injection": "command_injection",
        }
        for src_cat in sources:
            if src_cat not in sinks or not sinks[src_cat]:
                parent = sink_parents.get(src_cat)
                if parent and parent in sinks and sinks[parent]:
                    merged[lang]["sinks"][src_cat] = list(sinks[parent])
                    print(
                        f"  {lang}.sinks.{src_cat}: "
                        f"inherited {len(sinks[parent])} patterns from {parent}"
                    )
                    stats.setdefault(lang, {}).setdefault("inherited_sinks", 0)
                    stats[lang]["inherited_sinks"] += len(sinks[parent])

    # Validate
    print("\n── Validation ──")
    if not validate(original, merged):
        print("\n  Aborting — fix validation errors before writing.")
        return

    # Backup and write
    backup_path = TAINT_RULES_PATH.with_suffix(".yaml.bak")
    print(f"\n── Writing ──")
    print(f"  Backup: {backup_path}")

    # Preserve the original exact format by only adding new entries
    backup_path.write_text(TAINT_RULES_PATH.read_text(encoding="utf-8"))

    # Write merged result
    output = yaml.dump(
        merged,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )
    TAINT_RULES_PATH.write_text(output, encoding="utf-8")
    print(f"  Written: {TAINT_RULES_PATH}")

    # Summary
    print(f"\n── Summary ──")
    print(f"  Old size: {sum(len(str(v)) for v in original.values())} bytes")
    print(f"  New size: {len(output)} bytes")
    for lang, lang_stats in stats.items():
        parts = []
        if lang_stats.get("sources_added"):
            parts.append(f"+{lang_stats['sources_added']} sources")
        if lang_stats.get("sinks_added"):
            parts.append(f"+{lang_stats['sinks_added']} sinks")
        if lang_stats.get("fsb_sinks_added"):
            parts.append(f"+{lang_stats['fsb_sinks_added']} FSB sinks")
        if parts:
            print(f"  {lang}: {', '.join(parts)}")

    print("\n✅ Done. Run 'git diff src/hyqagent/cpg/taint_rules.yaml' to review.")


if __name__ == "__main__":
    main()
