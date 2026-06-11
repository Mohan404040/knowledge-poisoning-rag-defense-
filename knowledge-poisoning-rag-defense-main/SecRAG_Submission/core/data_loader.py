"""
data_loader.py — SecRAG Corpus Loader and Validation Utilities
==============================================================
SecRAG: Retrieval-Augmented Generation Security Framework
IEEE S&P Submission

Provides functions for loading, validating, and inspecting the four
SecRAG data files produced by ``core/poison_generator.py``:

    data/cves.json
    data/clean_documents.json
    data/poisoned_documents.json
    data/adaptive_poison.json

Typical usage::

    from utils.data_loader import load_corpus, validate_corpus, print_corpus_report

    corpus = load_corpus("./data")
    validate_corpus(corpus)
    print_corpus_report(corpus)
"""

from __future__ import annotations

import collections
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Expected document counts (used by validate_corpus)
EXPECTED_CVES: int = 80
EXPECTED_CLEAN: int = 320    # 80 CVEs × 4 source types
EXPECTED_POISON: int = 320   # 80 CVEs × 4 attack types
EXPECTED_ADAPTIVE: int = 240  # 80 CVEs × 3 adaptive strategies


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_json(path: str | Path) -> Any:
    """Load and return a JSON file, raising FileNotFoundError if absent."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Expected data file not found: {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_corpus(data_dir: str | Path = "./data") -> dict[str, Any]:
    """
    Load all four SecRAG corpus files from *data_dir*.

    Returns
    -------
    dict with keys:
        ``cves``       — list of CVE metadata dicts
        ``clean``      — list of clean document dicts
        ``poison``     — list of standard poison document dicts
        ``adaptive``   — list of adaptive poison document dicts
    """
    data_dir = Path(data_dir)
    logger.info("Loading SecRAG corpus from %s", data_dir)

    cve_data = load_json(data_dir / "cves.json")
    # cves.json may be wrapped in {"metadata": ..., "cves": [...]}
    cves = cve_data["cves"] if isinstance(cve_data, dict) and "cves" in cve_data else cve_data

    return {
        "cves": cves,
        "clean": load_json(data_dir / "clean_documents.json"),
        "poison": load_json(data_dir / "poisoned_documents.json"),
        "adaptive": load_json(data_dir / "adaptive_poison.json"),
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class CorpusValidationError(RuntimeError):
    """Raised when the loaded corpus fails a structural integrity check."""


def validate_corpus(corpus: dict[str, Any], strict: bool = True) -> dict[str, Any]:
    """
    Validate structural integrity of the SecRAG corpus.

    Checks performed
    ----------------
    1. Document counts match expected values (80 / 320 / 320 / 240).
    2. Every CVE has at least one clean and one poison document.
    3. Attack-type distribution is balanced across the four attack types.
    4. All adaptive documents carry an ``adaptive_strategy`` field.

    Parameters
    ----------
    corpus:
        Output of :func:`load_corpus`.
    strict:
        If ``True``, raise :class:`CorpusValidationError` on any failure.
        If ``False``, log warnings instead.

    Returns
    -------
    dict
        Summary statistics dict (same information printed by
        :func:`print_corpus_report`).
    """
    issues: list[str] = []

    def _check(condition: bool, message: str) -> None:
        if not condition:
            issues.append(message)

    cves = corpus["cves"]
    clean = corpus["clean"]
    poison = corpus["poison"]
    adaptive = corpus["adaptive"]

    # 1. Count checks
    _check(len(cves) == EXPECTED_CVES, f"CVE count: {len(cves)} (expected {EXPECTED_CVES})")
    _check(len(clean) == EXPECTED_CLEAN, f"Clean doc count: {len(clean)} (expected {EXPECTED_CLEAN})")
    _check(len(poison) == EXPECTED_POISON, f"Poison doc count: {len(poison)} (expected {EXPECTED_POISON})")
    _check(len(adaptive) == EXPECTED_ADAPTIVE, f"Adaptive doc count: {len(adaptive)} (expected {EXPECTED_ADAPTIVE})")

    # 2. CVE coverage
    all_cve_ids = {c["cve_id"] for c in cves}
    clean_cve_ids = {d["cve_id"] for d in clean}
    poison_cve_ids = {d["cve_id"] for d in poison}

    missing_clean = all_cve_ids - clean_cve_ids
    missing_poison = all_cve_ids - poison_cve_ids
    _check(not missing_clean, f"CVEs missing clean docs: {missing_clean}")
    _check(not missing_poison, f"CVEs missing poison docs: {missing_poison}")

    # 3. Attack-type balance
    attack_dist = collections.Counter(d["attack_type"] for d in poison)
    for atype in ("direct_contradiction", "partial_fix", "plausible_alternative", "context_manipulation"):
        _check(attack_dist.get(atype, 0) == EXPECTED_CVES, f"Attack type '{atype}': {attack_dist.get(atype,0)} docs (expected {EXPECTED_CVES})")

    # 4. Adaptive strategy field presence
    missing_strategy = [d["doc_id"] for d in adaptive if "adaptive_strategy" not in d]
    _check(not missing_strategy, f"Adaptive docs missing 'adaptive_strategy': {len(missing_strategy)}")

    stats = _compute_stats(corpus)

    if issues:
        joined = "\n  ".join(issues)
        msg = f"Corpus validation found {len(issues)} issue(s):\n  {joined}"
        if strict:
            raise CorpusValidationError(msg)
        logger.warning(msg)
    else:
        logger.info("Corpus validation passed — all checks OK.")

    return stats


def _compute_stats(corpus: dict[str, Any]) -> dict[str, Any]:
    """Return a statistics summary dict for the corpus."""
    clean = corpus["clean"]
    poison = corpus["poison"]
    adaptive = corpus["adaptive"]

    def word_stats(docs: list[dict]) -> dict:
        lengths = [len(d["content"].split()) for d in docs]
        if not lengths:
            return {"min": 0, "max": 0, "avg": 0}
        return {"min": min(lengths), "max": max(lengths), "avg": round(sum(lengths) / len(lengths))}

    return {
        "counts": {
            "cves": len(corpus["cves"]),
            "clean": len(clean),
            "poison": len(poison),
            "adaptive": len(adaptive),
            "total_documents": len(clean) + len(poison) + len(adaptive),
        },
        "coverage": {
            "clean_cves": len({d["cve_id"] for d in clean}),
            "poison_cves": len({d["cve_id"] for d in poison}),
            "adaptive_cves": len({d["cve_id"] for d in adaptive}),
        },
        "attack_type_distribution": dict(
            collections.Counter(d["attack_type"] for d in poison)
        ),
        "adaptive_strategy_distribution": dict(
            collections.Counter(d.get("adaptive_strategy", "unknown") for d in adaptive)
        ),
        "category_distribution": dict(
            collections.Counter(d["category"] for d in clean)
        ),
        "word_lengths": {
            "clean": word_stats(clean),
            "poison": word_stats(poison),
            "adaptive": word_stats(adaptive),
        },
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_corpus_report(corpus: dict[str, Any]) -> None:
    """
    Print a human-readable validation and statistics report to stdout.

    Also prints two sample documents (one clean, one partial-fix poison)
    for manual inspection of generation quality.
    """
    stats = _compute_stats(corpus)
    sep = "=" * 65

    print(f"\n{sep}")
    print("SECRAG DATA VALIDATION REPORT")
    print(sep)

    counts = stats["counts"]
    print(f"\nDocument counts:")
    print(f"  CVEs defined    : {counts['cves']}")
    print(f"  Clean docs      : {counts['clean']} / {EXPECTED_CLEAN}")
    print(f"  Poison docs     : {counts['poison']} / {EXPECTED_POISON}")
    print(f"  Adaptive docs   : {counts['adaptive']} / {EXPECTED_ADAPTIVE}")
    print(f"  TOTAL           : {counts['total_documents']} / 880")

    print(f"\nCVE coverage:")
    cov = stats["coverage"]
    print(f"  Clean           : {cov['clean_cves']} CVEs")
    print(f"  Poison          : {cov['poison_cves']} CVEs")
    print(f"  Adaptive        : {cov['adaptive_cves']} CVEs")

    print(f"\nAttack type distribution:")
    for atype, count in sorted(stats["attack_type_distribution"].items()):
        print(f"  {atype:<30} {count}")

    print(f"\nAdaptive strategy distribution:")
    for strat, count in sorted(stats["adaptive_strategy_distribution"].items()):
        print(f"  {strat:<30} {count}")

    print(f"\nCategory distribution (clean docs):")
    for cat, count in sorted(stats["category_distribution"].items()):
        print(f"  {cat:<30} {count} docs  ({count // 4} CVEs)")

    print(f"\nContent length (words):")
    for kind, wl in stats["word_lengths"].items():
        print(f"  {kind:<10}  min={wl['min']:>4}  max={wl['max']:>4}  avg={wl['avg']:>4}")

    # Sample documents
    sample_cve_id = "CVE-2024-3094"
    sample_clean = next(
        (d for d in corpus["clean"] if d["cve_id"] == sample_cve_id), None
    )
    sample_poison = next(
        (d for d in corpus["poison"]
         if d["cve_id"] == sample_cve_id and d["attack_type"] == "partial_fix"),
        None,
    )

    print(f"\n{sep}")
    print("SAMPLE DOCUMENTS — CVE-2024-3094")
    print(sep)

    if sample_clean:
        print(f"\n[CLEAN — {sample_clean['source_type']}]")
        print(sample_clean["content"][:500], "…")

    if sample_poison:
        print(f"\n[POISON — partial_fix]")
        print(sample_poison["content"][:500], "…")

    print()


# ---------------------------------------------------------------------------
# Convenience accessors
# ---------------------------------------------------------------------------

def get_documents_by_cve(corpus: dict[str, Any], cve_id: str) -> dict[str, list[dict]]:
    """
    Return all documents for a given CVE ID, grouped by corpus type.

    Returns
    -------
    dict with keys ``clean``, ``poison``, ``adaptive``.
    """
    return {
        "clean":    [d for d in corpus["clean"]    if d["cve_id"] == cve_id],
        "poison":   [d for d in corpus["poison"]   if d["cve_id"] == cve_id],
        "adaptive": [d for d in corpus["adaptive"] if d["cve_id"] == cve_id],
    }


def get_documents_by_category(
    corpus: dict[str, Any],
    category: str,
    doc_type: str = "clean",
) -> list[dict]:
    """
    Return all documents of *doc_type* belonging to a given CVE category.

    Parameters
    ----------
    doc_type:
        One of ``"clean"``, ``"poison"``, or ``"adaptive"``.
    """
    return [d for d in corpus[doc_type] if d["category"] == category]


def get_documents_by_attack_type(
    corpus: dict[str, Any],
    attack_type: str,
) -> list[dict]:
    """Return all poison documents matching *attack_type*."""
    return [d for d in corpus["poison"] if d["attack_type"] == attack_type]


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    data_dir = sys.argv[1] if len(sys.argv) > 1 else "./data"
    corpus = load_corpus(data_dir)
    validate_corpus(corpus, strict=False)
    print_corpus_report(corpus)
