"""
02_multi_embedding.py — Multi-Embedding Model Ablation Study
=============================================================
SecRAG: Retrieval-Augmented Generation Security Framework
IEEE S&P Submission

Evaluates whether the poison-retrieval vulnerability generalises across
three dense embedding models with different architectures and training
objectives:

    MiniLM   — sentence-transformers/all-MiniLM-L6-v2  (baseline)
    BGE-small — BAAI/bge-small-en-v1.5
    E5-small  — intfloat/e5-small-v2

For each model this experiment measures:
  1. Per-attack-type poison retrieval rate (1 poison doc / CVE)
  2. Overall poison retrieval rate under targeted attack (4 docs / CVE)

ASR (LLM-as-judge) is NOT run here; retrieval rates suffice to
demonstrate model-agnostic vulnerability (§5.2 of the paper).

Results are written to ``<output_dir>/02_multi_embedding.json``.

Usage::

    python experiments/02_multi_embedding.py \
        --data-dir ./data \
        --output-dir ./results
"""

from __future__ import annotations

import argparse
import gc
import json
import logging
import os
from collections import defaultdict
from pathlib import Path

from core.rag_pipeline import RAGPipeline, SUPPORTED_MODELS
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

# Model shorthand → HuggingFace path
EMBEDDING_MODELS: list[tuple[str, str]] = [
    ("sentence-transformers/all-MiniLM-L6-v2", "MiniLM"),
    ("BAAI/bge-small-en-v1.5",                 "BGE-small"),
    ("intfloat/e5-small-v2",                   "E5-small"),
]


# ---------------------------------------------------------------------------
# Per-model evaluation helpers
# ---------------------------------------------------------------------------

def _build_queries(cves: list[dict]) -> dict[str, str]:
    """Return {cve_id: query_string} for all CVEs."""
    return {
        c["cve_id"]: f"How do I remediate {c['cve_id']} ({c['affected_software']})?"
        for c in cves
    }


def _eval_attack_type(
    rag: RAGPipeline,
    cves: list[dict],
    clean_docs: list[dict],
    poison_docs: list[dict],
    queries: dict[str, str],
    attack_type: str,
    top_k: int = 3,
) -> dict:
    """
    Evaluate retrieval rate for one attack type (1 poison doc per CVE).

    Returns a dict with ``retrieval_rate`` and ``n_retrieved``.
    """
    # Build KB: all clean + one poison doc per CVE for this attack type
    kb = clean_docs.copy()
    seen: set[str] = set()
    for doc in poison_docs:
        if doc["attack_type"] == attack_type and doc["cve_id"] not in seen:
            kb.append(doc)
            seen.add(doc["cve_id"])

    rag.build_index(kb)

    retrieved_count = 0
    per_query: list[dict] = []

    for cve in cves:
        cve_id = cve["cve_id"]
        results = rag.retrieve(queries[cve_id], top_k=top_k)
        poison_hit = any(d.get("is_poisoned", False) for d in results)
        if poison_hit:
            retrieved_count += 1
        per_query.append({"cve_id": cve_id, "poison_retrieved": poison_hit})

    n = len(cves)
    return {
        "retrieval_rate": retrieved_count / n * 100,
        "n_retrieved": retrieved_count,
        "n_total": n,
        "per_query": per_query,
    }


def _eval_targeted(
    rag: RAGPipeline,
    cves: list[dict],
    clean_docs: list[dict],
    poison_docs: list[dict],
    queries: dict[str, str],
    n_per_cve: int = 4,
    top_k: int = 3,
) -> dict:
    """
    Evaluate retrieval rate under targeted attack (n_per_cve poison docs per CVE).

    Returns a dict with ``retrieval_rate`` and ``n_retrieved``.
    """
    kb = clean_docs.copy()
    by_cve: defaultdict[str, list] = defaultdict(list)
    for doc in poison_docs:
        by_cve[doc["cve_id"]].append(doc)
    for docs in by_cve.values():
        kb.extend(docs[:n_per_cve])

    rag.build_index(kb)

    retrieved_count = 0
    per_query: list[dict] = []

    for cve in cves:
        cve_id = cve["cve_id"]
        results = rag.retrieve(queries[cve_id], top_k=top_k)
        poison_hit = any(d.get("is_poisoned", False) for d in results)
        if poison_hit:
            retrieved_count += 1
        per_query.append({"cve_id": cve_id, "poison_retrieved": poison_hit})

    n = len(cves)
    return {
        "n_per_cve": n_per_cve,
        "retrieval_rate": retrieved_count / n * 100,
        "n_retrieved": retrieved_count,
        "n_total": n,
        "per_query": per_query,
    }


# ---------------------------------------------------------------------------
# Main experiment runner
# ---------------------------------------------------------------------------

def run(data_dir: str, output_dir: str, top_k: int = 3) -> dict:
    """
    Execute the multi-embedding ablation study.

    Parameters
    ----------
    data_dir:
        Path to directory containing the four SecRAG corpus JSON files.
    output_dir:
        Path to directory where ``02_multi_embedding.json`` will be written.
    top_k:
        Number of documents to retrieve per query.

    Returns
    -------
    dict
        Full results dict, also written to disk.
    """
    corpus = load_corpus(data_dir)
    cves        = corpus["cves"]
    clean_docs  = corpus["clean"]
    poison_docs = corpus["poison"]
    queries     = _build_queries(cves)

    all_results: dict[str, dict] = {}

    for model_path, model_name in EMBEDDING_MODELS:
        logger.info("=" * 60)
        logger.info("Embedding model: %s", model_name)
        logger.info("=" * 60)

        rag = RAGPipeline(model_path)
        model_results: dict[str, dict] = {}

        # 1. Per-attack-type retrieval (1 / CVE)
        type_results: dict[str, dict] = {}
        for attack_type in ATTACK_TYPES:
            logger.info("  Attack type: %s", attack_type)
            r = _eval_attack_type(
                rag, cves, clean_docs, poison_docs, queries, attack_type, top_k
            )
            type_results[attack_type] = r
            logger.info(
                "    Retrieval rate: %.1f%% (%d/%d)",
                r["retrieval_rate"], r["n_retrieved"], r["n_total"],
            )

        # 2. Targeted 4/CVE
        logger.info("  Targeted 4/CVE")
        targeted = _eval_targeted(rag, cves, clean_docs, poison_docs, queries, 4, top_k)
        logger.info(
            "    Retrieval rate: %.1f%% (%d/%d)",
            targeted["retrieval_rate"], targeted["n_retrieved"], targeted["n_total"],
        )

        model_results["model_path"]        = model_path
        model_results["attack_type_comparison"] = type_results
        model_results["targeted_4_per_cve"]     = targeted

        all_results[model_name] = model_results

        rag.unload()
        gc.collect()

    # ---- Summary table ----
    logger.info("")
    logger.info("Multi-Embedding Summary (Targeted 4/CVE):")
    for name, data in all_results.items():
        rr = data["targeted_4_per_cve"]["retrieval_rate"]
        logger.info("  %-12s  Retrieval=%.1f%%", name, rr)

    # Persist results
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    out_path = Path(output_dir) / "02_multi_embedding.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2)
    logger.info("Saved → %s", out_path)

    return all_results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecRAG Experiment 02 — Multi-Embedding Ablation"
    )
    parser.add_argument("--data-dir",   default="./data",    help="Input data directory")
    parser.add_argument("--output-dir", default="./results", help="Output directory")
    parser.add_argument("--top-k",      type=int, default=3, help="Retrieval top-k (default: 3)")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run(args.data_dir, args.output_dir, args.top_k)
