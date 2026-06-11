"""
07_incomplete_context_rate.py — Incomplete Context Rate Analysis
===============================================================
SecRAG: Retrieval-Augmented Generation Security Framework
IEEE S&P Submission

Measures the **Incomplete Context Rate (ICR)**: the fraction of queries for
which the retrieved context window is missing at least one ground-truth
remediation action type.

Three conditions are evaluated:

    clean_only               — clean-only knowledge base (baseline / upper bound)
    with_poison (poisoned)   — poisoned KB, query retrieved ≥1 poison doc
    poisoned_kb_clean_ret    — poisoned KB, query retrieved only clean docs

The experiment quantifies how much of the LLM generation-stage attack
susceptibility is attributable to the retrieval stage dropping required
action information (retrieval-stage incomplete context) versus the
LLM synthesising incomplete advice from a complete context
(generation-stage failure).

Results written to ``<output_dir>/07_incomplete_context_rate.json``.

Usage::

    python experiments/07_incomplete_context_rate.py \
        --data-dir ./data \
        --output-dir ./results
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from pathlib import Path

import numpy as np

from core.rag_pipeline import RAGPipeline
from core.action_extractor import ActionExtractor
from utils.data_loader import load_corpus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

EMBEDDING_MODEL   = "sentence-transformers/all-MiniLM-L6-v2"
N_POISON_PER_CVE  = 4
TOP_K             = 3

# Ground-truth action prefix → action-keyword category mapping
# (aligned with ActionExtractor.ACTION_KEYWORDS keys)
_GT_TO_KEYWORD_MAP: dict[str, str] = {
    "update_package":              "update",
    "apply_patch":                 "update",
    "uninstall_software":          "update",
    "rotate_ssh_keys":             "rotate",
    "rotate_credentials":          "rotate",
    "audit_logs":                  "audit",
    "review_logs":                 "audit",
    "check_iocs":                  "ioc",
    "verify_integrity":            "verify",
    "verify_config":               "verify",
    "scan_dependencies":           "verify",
    "restart_service":             "restart",
    "isolate_systems":             "isolate",
    "disable_feature":             "disable",
    "disable_ciphers":             "disable",
    "disable_mac":                 "disable",
    "review_config":               "config",
    "configure_rate_limiting":     "config",
    "monitor_performance":         "config",
    "enable_feature":              "enable",
    "enable_amsi":                 "enable",
    "enable_message_authenticator":"enable",
    "factory_reset":               "factory_reset",
    "block_outbound":              "block",
    "apply_firewall":              "block",
    "restrict_access":             "block",
    "remove_accounts":             "remove_accounts",
    "revoke_tokens":               "remove_accounts",
    "notify_security":             "notify",
    "migrate_to":                  "config",
    "set_property":                "config",
    "configure_policy":            "config",
    "enforce_policy":              "enable",
}


def _map_gt_to_keyword_types(ground_truth_actions: list[str]) -> set[str]:
    """
    Convert a CVE's ground-truth action list to the smaller set of
    action-keyword category labels used by :class:`ActionExtractor`.

    Action strings of the form ``"prefix:detail"`` are handled by
    splitting on ``":"`` and looking up only the prefix.
    """
    types: set[str] = set()
    for action in ground_truth_actions:
        prefix = action.split(":")[0]
        mapped = _GT_TO_KEYWORD_MAP.get(prefix)
        if mapped:
            types.add(mapped)
    return types


def _extract_context_actions(docs: list[dict]) -> set[str]:
    """Return the union of action types found across all documents in *docs*."""
    found: set[str] = set()
    for doc in docs:
        found |= ActionExtractor.extract_actions(doc["content"])
    return found


def _icr_stats(records: list[dict]) -> tuple[float, float, int]:
    """Return (icr_pct, mean_recall, n) for a list of per-CVE ICR records."""
    if not records:
        return 0.0, 0.0, 0
    icr  = sum(1 for r in records if r["is_incomplete"]) / len(records) * 100
    mean = float(np.mean([r["recall"] for r in records]))
    return icr, mean, len(records)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(data_dir: str, output_dir: str, n_poison_per_cve: int = N_POISON_PER_CVE) -> dict:
    """
    Compute the Incomplete Context Rate for three retrieval conditions.

    Parameters
    ----------
    data_dir:
        SecRAG corpus directory.
    output_dir:
        Results output directory.
    n_poison_per_cve:
        Number of poison documents per CVE in the poisoned KB.

    Returns
    -------
    dict with ``"summary"`` and ``"details"`` keys.
    """
    corpus     = load_corpus(data_dir)
    cves       = corpus["cves"]
    clean_docs = corpus["clean"]
    poison_docs = corpus["poison"]

    queries = {
        c["cve_id"]: f"How do I remediate {c['cve_id']} ({c['affected_software']})?"
        for c in cves
    }

    # ---- Build knowledge bases ----
    kb_poison = clean_docs.copy()
    by_cve: defaultdict[str, list] = defaultdict(list)
    for doc in poison_docs:
        by_cve[doc["cve_id"]].append(doc)
    for docs in by_cve.values():
        kb_poison.extend(docs[:n_poison_per_cve])

    logger.info("Building clean-only index (%d docs)…", len(clean_docs))
    rag_clean  = RAGPipeline(EMBEDDING_MODEL)
    rag_clean.build_index(clean_docs)

    logger.info("Building poisoned index (%d docs)…", len(kb_poison))
    rag_poison = RAGPipeline(EMBEDDING_MODEL)
    rag_poison.build_index(kb_poison)

    # ---- Per-CVE analysis ----
    results: dict[str, list[dict]] = {
        "clean_only":              [],
        "with_poison":             [],
        "poisoned_kb_clean_ret":   [],
    }

    for cve in cves:
        cve_id = cve["cve_id"]
        query  = queries[cve_id]
        gt_types = _map_gt_to_keyword_types(cve["ground_truth_actions"])

        if not gt_types:
            continue

        # --- Clean-only KB ---
        clean_retrieved = rag_clean.retrieve(query, top_k=TOP_K)
        clean_ctx_actions = _extract_context_actions(clean_retrieved)
        missing_clean = gt_types - clean_ctx_actions
        recall_clean  = len(gt_types & clean_ctx_actions) / len(gt_types)

        results["clean_only"].append({
            "cve_id":       cve_id,
            "gt_types":     sorted(gt_types),
            "ctx_types":    sorted(clean_ctx_actions),
            "missing":      sorted(missing_clean),
            "is_incomplete":len(missing_clean) > 0,
            "recall":       recall_clean,
        })

        # --- Poisoned KB ---
        poison_retrieved = rag_poison.retrieve(query, top_k=TOP_K)
        has_poison       = any(d.get("is_poisoned", False) for d in poison_retrieved)
        pois_ctx_actions = _extract_context_actions(poison_retrieved)
        missing_pois     = gt_types - pois_ctx_actions
        recall_pois      = len(gt_types & pois_ctx_actions) / len(gt_types)

        bucket = "with_poison" if has_poison else "poisoned_kb_clean_ret"
        results[bucket].append({
            "cve_id":       cve_id,
            "gt_types":     sorted(gt_types),
            "ctx_types":    sorted(pois_ctx_actions),
            "missing":      sorted(missing_pois),
            "is_incomplete":len(missing_pois) > 0,
            "recall":       recall_pois,
            "has_poison":   has_poison,
        })

    rag_clean.unload()
    rag_poison.unload()

    # ---- Aggregate stats ----
    icr_c,  recall_c,  n_c  = _icr_stats(results["clean_only"])
    icr_p,  recall_p,  n_p  = _icr_stats(results["with_poison"])
    icr_pk, recall_pk, n_pk = _icr_stats(results["poisoned_kb_clean_ret"])

    logger.info("")
    logger.info("%-35s %-10s %-12s %-5s", "Condition", "ICR", "Avg Recall", "N")
    logger.info("-" * 62)
    logger.info("%-35s %.1f%%     %.3f        %d", "Clean KB only",             icr_c,  recall_c,  n_c)
    logger.info("%-35s %.1f%%     %.3f        %d", "Poisoned KB, poison retr.",  icr_p,  recall_p,  n_p)
    logger.info("%-35s %.1f%%     %.3f        %d", "Poisoned KB, clean retr.",   icr_pk, recall_pk, n_pk)

    summary = {
        "clean_only":            {"icr": icr_c,  "avg_recall": recall_c,  "n": n_c},
        "with_poison":           {"icr": icr_p,  "avg_recall": recall_p,  "n": n_p},
        "poisoned_kb_clean_ret": {"icr": icr_pk, "avg_recall": recall_pk, "n": n_pk},
    }

    output = {"summary": summary, "details": results}
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    out_path = Path(output_dir) / "07_incomplete_context_rate.json"
    with open(out_path, "w") as fh:
        json.dump(output, fh, indent=2)
    logger.info("Saved → %s", out_path)

    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecRAG Experiment 07 — Incomplete Context Rate"
    )
    parser.add_argument("--data-dir",   default="./data",    help="Input data directory")
    parser.add_argument("--output-dir", default="./results", help="Output directory")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run(args.data_dir, args.output_dir)
