"""
08_conditional_asr_deep.py — Conditional ASR Deep Analysis & Majority-Vote Baseline
====================================================================================
SecRAG: Retrieval-Augmented Generation Security Framework
IEEE S&P Submission

Two sub-experiments:

**Sub-experiment A — Conditional ASR Deep Analysis (§5.4)**
    Disaggregates the conditional ASR (attack success rate given poison
    was retrieved) along three dimensions using the no-defence ablation
    results as input:

    1. By poison rank — does rank-1 poison cause more successful attacks
       than rank-2 or rank-3 poison?
    2. By co-retrieval pattern — does the number of clean documents
       co-retrieved with poison affect susceptibility?
    3. By CVE category — which vulnerability categories are most susceptible?

**Sub-experiment B — Majority-Vote Baseline Defense (§5.5)**
    Implements a simple action-consensus baseline: an action must appear
    in >50% of retrieved documents to be considered "majority-endorsed";
    any document missing >50% of those majority actions is flagged as
    anomalous.

    Detection precision, recall, and F1 are computed and compared against
    the full five-layer SecRAG defence.

    Requires ``01a_defense_ablation.json`` to already exist in
    *results_dir* so it can load the no-defence per-query results.

Results written to:
    ``<output_dir>/08a_conditional_asr_deep.json``
    ``<output_dir>/08b_majority_vote.json``

Usage::

    python experiments/08_conditional_asr_deep.py \
        --data-dir ./data \
        --results-dir ./results \
        --output-dir ./results
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from core.rag_pipeline import RAGPipeline
from core.action_extractor import ActionExtractor
from core.metrics import Metrics
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_queries(cves: list[dict]) -> dict[str, str]:
    return {
        c["cve_id"]: f"How do I remediate {c['cve_id']} ({c['affected_software']})?"
        for c in cves
    }


def _build_targeted_kb(clean: list[dict], poison: list[dict], n: int = 4) -> list[dict]:
    kb = clean.copy()
    by_cve: defaultdict[str, list] = defaultdict(list)
    for doc in poison:
        by_cve[doc["cve_id"]].append(doc)
    for docs in by_cve.values():
        kb.extend(docs[:n])
    return kb


def _load_no_defence_results(results_dir: str) -> list[dict]:
    """Load the 'No defence' per-query results from 01a_defense_ablation.json."""
    ablation_path = Path(results_dir) / "01a_defense_ablation.json"
    if not ablation_path.exists():
        logger.warning("01a_defense_ablation.json not found in %s — "
                       "conditional ASR sub-experiment will be skipped.", results_dir)
        return []
    with open(ablation_path) as fh:
        data = json.load(fh)
    no_def = data.get("No defence", {})
    return no_def.get("results", [])


# ---------------------------------------------------------------------------
# Sub-experiment A — Conditional ASR deep analysis
# ---------------------------------------------------------------------------

def run_conditional_analysis(
    cves: list[dict],
    queries: dict[str, str],
    rag: RAGPipeline,
    no_def_results: list[dict],
) -> dict:
    """
    Disaggregate conditional ASR by poison rank, co-retrieval pattern,
    and CVE category.

    Parameters
    ----------
    cves:
        CVE metadata list.
    queries:
        Pre-built query strings.
    rag:
        :class:`RAGPipeline` with the targeted KB indexed.
    no_def_results:
        Per-query results from the no-defence ablation run (used for
        ``attack_successful`` labels).

    Returns
    -------
    dict with ``"by_rank"``, ``"by_coretrieval"``, and ``"by_category"`` sub-dicts.
    """
    # Build a lookup from cve_id → no-defence result for O(1) access
    no_def_map: dict[str, dict] = {r["cve_id"]: r for r in no_def_results}

    rank_analysis: dict[str, dict[str, int]] = {
        "rank_1": {"total": 0, "successful": 0},
        "rank_2": {"total": 0, "successful": 0},
        "rank_3": {"total": 0, "successful": 0},
    }
    coretrieval_analysis: dict[str, dict[str, int]] = {}
    cat_analysis: defaultdict[str, dict[str, int]] = defaultdict(
        lambda: {"retrieved": 0, "successful": 0}
    )

    for cve in cves:
        cve_id    = cve["cve_id"]
        retrieved = rag.retrieve(queries[cve_id], top_k=TOP_K)

        poison_docs = [d for d in retrieved if d.get("is_poisoned", False)]
        if not poison_docs:
            continue

        nd_result = no_def_map.get(cve_id)
        if nd_result is None:
            continue
        was_successful = nd_result.get("attack_successful", False)

        # ---- By rank ----
        highest_rank = min(d["retrieval_rank"] for d in poison_docs)
        rkey = f"rank_{highest_rank}"
        if rkey in rank_analysis:
            rank_analysis[rkey]["total"] += 1
            if was_successful:
                rank_analysis[rkey]["successful"] += 1

        # ---- By co-retrieval pattern ----
        n_poison = len(poison_docs)
        n_clean  = len(retrieved) - n_poison
        ckey     = f"{n_poison}p_{n_clean}c"
        if ckey not in coretrieval_analysis:
            coretrieval_analysis[ckey] = {"total": 0, "successful": 0}
        coretrieval_analysis[ckey]["total"] += 1
        if was_successful:
            coretrieval_analysis[ckey]["successful"] += 1

        # ---- By category ----
        cat_analysis[cve["category"]]["retrieved"] += 1
        if was_successful:
            cat_analysis[cve["category"]]["successful"] += 1

    # ---- Print tables ----
    logger.info("\nConditional ASR by Poison Rank:")
    logger.info("%-10s %-10s %-12s %-10s", "Rank", "Total", "Successful", "Cond ASR")
    logger.info("-" * 42)
    for rk, d in rank_analysis.items():
        cond = d["successful"] / d["total"] * 100 if d["total"] > 0 else 0.0
        logger.info("%-10s %-10d %-12d %.1f%%", rk, d["total"], d["successful"], cond)

    logger.info("\nConditional ASR by Co-retrieval Pattern:")
    logger.info("%-15s %-10s %-12s %-10s", "Pattern", "Total", "Successful", "Cond ASR")
    logger.info("-" * 47)
    for ck in sorted(coretrieval_analysis):
        d    = coretrieval_analysis[ck]
        cond = d["successful"] / d["total"] * 100 if d["total"] > 0 else 0.0
        logger.info("%-15s %-10d %-12d %.1f%%", ck, d["total"], d["successful"], cond)

    logger.info("\nConditional ASR by Category:")
    logger.info("%-25s %-12s %-12s %-10s", "Category", "Retrieved", "Successful", "Cond ASR")
    logger.info("-" * 59)
    for cat in sorted(cat_analysis):
        d    = cat_analysis[cat]
        cond = d["successful"] / d["retrieved"] * 100 if d["retrieved"] > 0 else 0.0
        logger.info("%-25s %-12d %-12d %.1f%%", cat, d["retrieved"], d["successful"], cond)

    return {
        "by_rank":        rank_analysis,
        "by_coretrieval": coretrieval_analysis,
        "by_category":    dict(cat_analysis),
    }


# ---------------------------------------------------------------------------
# Sub-experiment B — Majority-vote baseline
# ---------------------------------------------------------------------------

def run_majority_vote(
    cves: list[dict],
    queries: dict[str, str],
    rag: RAGPipeline,
    secrag_results: dict | None = None,
) -> dict:
    """
    Majority-vote action-consensus baseline defence.

    An action type is *majority-endorsed* if it appears in >50% of
    retrieved documents.  A document is flagged (predicted poisoned) if its
    action-type overlap with the majority-endorsed set falls below 50%.

    Parameters
    ----------
    cves:
        CVE metadata list.
    queries:
        Pre-built query strings.
    rag:
        :class:`RAGPipeline` with the targeted KB indexed.
    secrag_results:
        Loaded SecRAG ``"Full SecRAG (τ=0.45)"`` ablation dict for comparison
        printing.  Pass ``None`` to skip the comparison table.

    Returns
    -------
    dict
        Precision, recall, F1, and confusion-matrix counts.
    """
    mv_detections: list[dict] = []

    for cve in cves:
        cve_id    = cve["cve_id"]
        retrieved = rag.retrieve(queries[cve_id], top_k=TOP_K)

        # Compute action sets per document
        doc_action_sets = [ActionExtractor.extract_actions(d["content"]) for d in retrieved]

        # Majority-endorsed actions (appear in >50% of documents)
        action_counts: Counter = Counter()
        for actions in doc_action_sets:
            for a in actions:
                action_counts[a] += 1
        majority_threshold = len(retrieved) / 2
        majority_actions   = {a for a, c in action_counts.items() if c > majority_threshold}

        for doc, actions in zip(retrieved, doc_action_sets):
            if majority_actions:
                overlap      = len(actions & majority_actions) / len(majority_actions)
                is_flagged   = overlap < 0.5
            else:
                is_flagged   = False

            mv_detections.append({
                "actual_poison":    doc.get("is_poisoned", False),
                "predicted_poison": is_flagged,
            })

    dm = Metrics.detection_metrics(mv_detections)

    logger.info("")
    logger.info("%-30s %-10s %-10s %-10s", "Method", "Prec", "Recall", "F1")
    logger.info("-" * 60)
    logger.info(
        "%-30s %.1f%%     %.1f%%     %.1f%%",
        "Majority Vote",
        dm["precision"] * 100, dm["recall"] * 100, dm["f1"] * 100,
    )
    if secrag_results:
        logger.info(
            "%-30s %.1f%%     %.1f%%     %.1f%%",
            "Full SecRAG (τ=0.45)",
            secrag_results.get("precision", 0),
            secrag_results.get("recall", 0),
            secrag_results.get("f1", 0),
        )

    return {
        "precision": dm["precision"] * 100,
        "recall":    dm["recall"]    * 100,
        "f1":        dm["f1"]        * 100,
        "tp": dm["tp"], "fp": dm["fp"], "fn": dm["fn"], "tn": dm["tn"],
    }


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(
    data_dir: str,
    results_dir: str,
    output_dir: str,
) -> dict[str, Any]:
    """
    Execute sub-experiment A (conditional ASR deep analysis) and
    sub-experiment B (majority-vote baseline).

    Parameters
    ----------
    data_dir:
        SecRAG corpus directory.
    results_dir:
        Directory containing ``01a_defense_ablation.json``.
    output_dir:
        Output directory for this experiment's results.
    """
    corpus     = load_corpus(data_dir)
    cves       = corpus["cves"]
    queries    = _build_queries(cves)

    kb = _build_targeted_kb(corpus["clean"], corpus["poison"], N_POISON_PER_CVE)
    rag = RAGPipeline(EMBEDDING_MODEL)
    rag.build_index(kb)

    # Load no-defence ablation results for Sub-experiment A
    no_def_results = _load_no_defence_results(results_dir)

    # ---- Sub-experiment A ----
    logger.info("=" * 60)
    logger.info("SUB-EXPERIMENT A — CONDITIONAL ASR DEEP ANALYSIS")
    logger.info("=" * 60)
    if no_def_results:
        cond_analysis = run_conditional_analysis(cves, queries, rag, no_def_results)
    else:
        logger.warning("Skipping conditional analysis — no-defence results unavailable.")
        cond_analysis = {}

    # ---- Sub-experiment B ----
    logger.info("")
    logger.info("=" * 60)
    logger.info("SUB-EXPERIMENT B — MAJORITY-VOTE BASELINE DEFENCE")
    logger.info("=" * 60)

    # Load SecRAG results for comparison (optional)
    secrag_comparison: dict | None = None
    ablation_path = Path(results_dir) / "01a_defense_ablation.json"
    if ablation_path.exists():
        with open(ablation_path) as fh:
            abl = json.load(fh)
        secrag_comparison = abl.get("Full SecRAG (τ=0.45)")

    mv_results = run_majority_vote(cves, queries, rag, secrag_comparison)

    rag.unload()

    # Persist
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    with open(Path(output_dir) / "08a_conditional_asr_deep.json", "w") as fh:
        json.dump(cond_analysis, fh, indent=2)
    with open(Path(output_dir) / "08b_majority_vote.json", "w") as fh:
        json.dump(mv_results, fh, indent=2)
    logger.info("Saved → %s/08a_conditional_asr_deep.json", output_dir)
    logger.info("Saved → %s/08b_majority_vote.json",        output_dir)

    return {"conditional_analysis": cond_analysis, "majority_vote": mv_results}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecRAG Experiment 08 — Conditional ASR Deep Analysis & Majority-Vote Baseline"
    )
    parser.add_argument("--data-dir",    default="./data",    help="Input data directory")
    parser.add_argument("--results-dir", default="./results", help="Directory with NB3 results")
    parser.add_argument("--output-dir",  default="./results", help="Output directory")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run(args.data_dir, args.results_dir, args.output_dir)
