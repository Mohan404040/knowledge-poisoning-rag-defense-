"""
04_embedding_similarity.py — Embedding Similarity Analysis
==========================================================
SecRAG: Retrieval-Augmented Generation Security Framework
IEEE S&P Submission

Computes the cosine similarity between each poison document's embedding
and its CVE's query embedding, compared against the corresponding clean
document embeddings.  The key question: do poison documents occupy the
*same embedding neighbourhood* as legitimate documents?

For each (CVE, attack_type) pair this experiment measures:
  - ``poison_query_sim``  — cosine similarity between poison doc and query
  - ``clean_mean_sim``    — mean cosine similarity of clean docs to query
  - ``clean_3rd_sim``     — similarity of the 3rd-ranked clean doc (retrieval
                            threshold proxy: poison is retrieved if it exceeds this)
  - ``would_retrieve``    — boolean flag: poison_query_sim > clean_3rd_sim

Results are written to ``<output_dir>/04_embedding_similarity.json``.

Usage::

    python experiments/04_embedding_similarity.py \
        --data-dir ./data \
        --output-dir ./results \
        [--model MiniLM]
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np

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


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------

def compute_embedding_similarity(
    cves: list[dict],
    clean_docs: list[dict],
    poison_docs: list[dict],
    rag: RAGPipeline,
) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    """
    Compute per-document embedding similarity metrics.

    For each CVE the query embedding is computed once, then compared against
    all clean document embeddings (to establish the retrieval threshold) and
    all poison document embeddings.

    Parameters
    ----------
    cves:
        List of CVE metadata dicts.
    clean_docs:
        List of clean document dicts.
    poison_docs:
        List of poisoned document dicts.
    rag:
        Initialised :class:`RAGPipeline` instance (model loaded, index not required).

    Returns
    -------
    (per_document, summary) : tuple
        ``per_document`` — mapping from attack_type → list of per-document result dicts.
        ``summary``      — mapping from attack_type → aggregate stats dict.
    """
    per_document: dict[str, list[dict]] = {atype: [] for atype in ATTACK_TYPES}

    for i, cve in enumerate(cves):
        cve_id = cve["cve_id"]
        query  = f"How do I remediate {cve_id} ({cve['affected_software']})?"

        # --- Query embedding ---
        query_emb = rag.get_embedding(query)

        # --- Clean document similarities ---
        cve_clean = [d for d in clean_docs if d["cve_id"] == cve_id]
        if not cve_clean:
            continue

        clean_embs = [rag.get_embedding(d["content"]) for d in cve_clean]
        clean_sims = sorted(
            [float(np.dot(query_emb, e)) for e in clean_embs],
            reverse=True,
        )

        # Retrieval threshold: similarity of the 3rd-ranked clean document
        threshold = clean_sims[2] if len(clean_sims) >= 3 else clean_sims[-1]
        mean_clean_sim = float(np.mean(clean_sims))

        # --- Poison document similarities ---
        for attack_type in ATTACK_TYPES:
            cve_poison = [
                d for d in poison_docs
                if d["cve_id"] == cve_id and d["attack_type"] == attack_type
            ]

            for p_doc in cve_poison:
                p_emb       = rag.get_embedding(p_doc["content"])
                poison_sim  = float(np.dot(query_emb, p_emb))
                would_retrieve = poison_sim > threshold

                per_document[attack_type].append(
                    {
                        "cve_id":          cve_id,
                        "doc_id":          p_doc["doc_id"],
                        "poison_query_sim": poison_sim,
                        "clean_mean_sim":   mean_clean_sim,
                        "clean_3rd_sim":    threshold,
                        "would_retrieve":   would_retrieve,
                    }
                )

        if (i + 1) % 10 == 0:
            logger.info("  Processed %d/%d CVEs…", i + 1, len(cves))

    # Aggregate summary
    summary: dict[str, dict] = {}
    for atype in ATTACK_TYPES:
        records = per_document[atype]
        if records:
            sims      = [r["poison_query_sim"] for r in records]
            retrieves = [r["would_retrieve"]    for r in records]
            summary[atype] = {
                "mean_similarity":    float(np.mean(sims)),
                "std_similarity":     float(np.std(sims)),
                "pct_would_retrieve": float(np.mean(retrieves) * 100),
                "n_documents":        len(records),
            }
        else:
            summary[atype] = {
                "mean_similarity": 0.0, "std_similarity": 0.0,
                "pct_would_retrieve": 0.0, "n_documents": 0,
            }

    return per_document, summary


# ---------------------------------------------------------------------------
# Main experiment runner
# ---------------------------------------------------------------------------

def run(data_dir: str, output_dir: str, model_name: str = "MiniLM") -> dict:
    """
    Execute the embedding similarity analysis.

    Parameters
    ----------
    data_dir:
        Path to the SecRAG corpus directory.
    output_dir:
        Path to write ``04_embedding_similarity.json``.
    model_name:
        Short alias or full HuggingFace model ID to use for embedding.

    Returns
    -------
    dict
        Full results dict with ``"model"``, ``"per_document"``, and ``"summary"`` keys.
    """
    corpus = load_corpus(data_dir)

    model_path = SUPPORTED_MODELS.get(model_name, model_name)
    logger.info("Embedding similarity analysis with: %s", model_path)

    rag = RAGPipeline(model_path)

    per_document, summary = compute_embedding_similarity(
        corpus["cves"], corpus["clean"], corpus["poison"], rag
    )

    rag.unload()

    # Print summary table
    logger.info("")
    logger.info("Embedding Similarity — Poison vs Query (cosine):")
    logger.info("%-28s %-14s %-20s", "Attack Type", "Mean Sim", "% Would Retrieve")
    logger.info("-" * 64)
    for atype in ATTACK_TYPES:
        s = summary[atype]
        logger.info(
            "%-28s %.4f         %.1f%%",
            atype, s["mean_similarity"], s["pct_would_retrieve"],
        )

    result = {
        "model": model_path,
        "per_document": per_document,
        "summary": summary,
    }

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    out_path = Path(output_dir) / "04_embedding_similarity.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    logger.info("Saved → %s", out_path)

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecRAG Experiment 04 — Embedding Similarity Analysis"
    )
    parser.add_argument("--data-dir",   default="./data",    help="Input data directory")
    parser.add_argument("--output-dir", default="./results", help="Output directory")
    parser.add_argument(
        "--model",
        default="MiniLM",
        choices=list(SUPPORTED_MODELS.keys()) + list(SUPPORTED_MODELS.values()),
        help="Embedding model alias or full HuggingFace ID (default: MiniLM)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run(args.data_dir, args.output_dir, args.model)
