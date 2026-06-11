"""
03_vocabulary_overlap.py — Vocabulary Overlap Analysis
======================================================
SecRAG: Retrieval-Augmented Generation Security Framework
IEEE S&P Submission

Measures the lexical similarity between poison and clean documents for
each CVE using token-level Jaccard similarity (vocabulary overlap).

High overlap explains *why* poison documents are retrieved for the
correct query despite containing misleading remediation advice — they
share substantial vocabulary with the legitimate documents they mimic.

Results are written to ``<output_dir>/03_vocabulary_overlap.json``.

Metrics computed per (CVE, attack_type) pair:
  - mean Jaccard overlap across all (poison, clean) document pairs
  - maximum Jaccard overlap across all (poison, clean) document pairs

Usage::

    python experiments/03_vocabulary_overlap.py \
        --data-dir ./data \
        --output-dir ./results
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np

from core.metrics import Metrics
from utils.data_loader import load_corpus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

ATTACK_TYPES = [
    "direct_contradiction",
    "partial_fix",
    "plausible_alternative",
    "context_manipulation",
]


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------

def compute_vocabulary_overlap(
    cves: list[dict],
    clean_docs: list[dict],
    poison_docs: list[dict],
) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    """
    Compute Jaccard vocabulary overlap for every (poison, clean) document pair.

    For each CVE and each attack type we compute:
      - mean overlap: average Jaccard similarity across all poison–clean pairs
      - max overlap: highest single-pair Jaccard similarity

    Parameters
    ----------
    cves:
        List of CVE metadata dicts.
    clean_docs:
        List of clean document dicts.
    poison_docs:
        List of poisoned document dicts.

    Returns
    -------
    (per_document, summary) : tuple
        ``per_document`` — mapping from attack_type → list of per-CVE result dicts.
        ``summary``      — mapping from attack_type → aggregate stats dict.
    """
    per_document: dict[str, list[dict]] = {atype: [] for atype in ATTACK_TYPES}

    for cve in cves:
        cve_id = cve["cve_id"]
        cve_clean = [d for d in clean_docs if d["cve_id"] == cve_id]

        if not cve_clean:
            continue

        for attack_type in ATTACK_TYPES:
            cve_poison = [
                d for d in poison_docs
                if d["cve_id"] == cve_id and d["attack_type"] == attack_type
            ]

            for p_doc in cve_poison:
                overlaps = [
                    Metrics.vocabulary_overlap(p_doc["content"], c_doc["content"])
                    for c_doc in cve_clean
                ]
                if overlaps:
                    per_document[attack_type].append(
                        {
                            "cve_id": cve_id,
                            "doc_id": p_doc["doc_id"],
                            "mean_overlap": float(np.mean(overlaps)),
                            "max_overlap":  float(max(overlaps)),
                            "n_clean_compared": len(overlaps),
                        }
                    )

    # Aggregate summary per attack type
    summary: dict[str, dict] = {}
    for atype in ATTACK_TYPES:
        records = per_document[atype]
        if records:
            means = [r["mean_overlap"] for r in records]
            maxes = [r["max_overlap"]  for r in records]
            summary[atype] = {
                "mean_jaccard": float(np.mean(means)),
                "std_jaccard":  float(np.std(means)),
                "max_jaccard":  float(max(maxes)),
                "n_documents":  len(records),
            }
        else:
            summary[atype] = {
                "mean_jaccard": 0.0, "std_jaccard": 0.0,
                "max_jaccard": 0.0,  "n_documents": 0,
            }

    return per_document, summary


# ---------------------------------------------------------------------------
# Main experiment runner
# ---------------------------------------------------------------------------

def run(data_dir: str, output_dir: str) -> dict:
    """
    Execute the vocabulary overlap analysis.

    Parameters
    ----------
    data_dir:
        Path to the SecRAG corpus directory.
    output_dir:
        Path to write ``03_vocabulary_overlap.json``.

    Returns
    -------
    dict
        Full results dict with ``"per_document"`` and ``"summary"`` keys.
    """
    corpus = load_corpus(data_dir)
    per_document, summary = compute_vocabulary_overlap(
        corpus["cves"], corpus["clean"], corpus["poison"]
    )

    # Print summary table
    logger.info("")
    logger.info("Vocabulary Overlap with Clean Documents (Jaccard Similarity):")
    logger.info("%-28s %-14s %-10s %-10s", "Attack Type", "Mean Jaccard", "Std", "Max")
    logger.info("-" * 65)
    for atype in ATTACK_TYPES:
        s = summary[atype]
        logger.info(
            "%-28s %.4f         %.4f     %.4f",
            atype, s["mean_jaccard"], s["std_jaccard"], s["max_jaccard"],
        )

    result = {"per_document": per_document, "summary": summary}

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    out_path = Path(output_dir) / "03_vocabulary_overlap.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    logger.info("Saved → %s", out_path)

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecRAG Experiment 03 — Vocabulary Overlap Analysis"
    )
    parser.add_argument("--data-dir",   default="./data",    help="Input data directory")
    parser.add_argument("--output-dir", default="./results", help="Output directory")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run(args.data_dir, args.output_dir)
