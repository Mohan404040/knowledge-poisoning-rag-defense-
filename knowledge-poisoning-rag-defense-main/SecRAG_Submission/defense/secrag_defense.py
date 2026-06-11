"""
secrag_defense.py — SecRAG Multi-Layer Defense System
======================================================
SecRAG: Retrieval-Augmented Generation Security Framework
IEEE S&P Submission

Implements the five-layer trust-scoring system described in §4 of the paper.
Each retrieved document is assigned a composite trust score:

    S(d) = Σ_l  w_l · s_l(d)  /  Σ_l  w_l          (Equation 1)

where the sum runs over the *active* subset of layers (enabling per-layer
ablation without reweighting the full five-layer system).

Layer definitions
-----------------
Layer 1 — Source Reputation   (w=0.15)
    Static lookup of the document's ``source_type`` field against a
    hand-curated reputation table (vendor advisories: 0.95, community
    forums: 0.30, etc.).

Layer 2 — Semantic Consistency (w=0.20)
    Mean cosine similarity between the document and all other documents
    in the same retrieved set.  Outlier documents score low.

Layer 3 — Contradiction Detection (w=0.25)
    LLM-as-judge comparison of the document against the highest-reputation
    document in the retrieved set.  Returns a [0, 1] trust score.

Layer 4 — Action Graph Completeness (w=0.25)
    Regex-based action diversity score from
    :meth:`ActionExtractor.compute_action_score`.  Documents that claim
    completeness while omitting critical steps are penalised.

Layer 5 — Majority-Action Voting (w=0.15)
    Jaccard overlap between the document's action set and the union of
    action sets from all other retrieved documents.

Usage::

    from core.secrag_defense import SecRAGDefense

    defense = SecRAGDefense("sentence-transformers/all-MiniLM-L6-v2")
    filtered, removed = defense.filter_documents(
        retrieved_docs, cve_id, threshold=0.45
    )
    defense.unload()
"""

from __future__ import annotations

import gc
import json
import logging
import time
from typing import Any

import numpy as np
from sentence_transformers import SentenceTransformer

from core.action_extractor import ActionExtractor

logger = logging.getLogger(__name__)

_REQUEST_DELAY: float = 2.5
_MAX_RETRIES:   int   = 5


# ---------------------------------------------------------------------------
# Reputation table
# ---------------------------------------------------------------------------

REPUTATION_SCORES: dict[str, float] = {
    "vendor_advisory":  0.95,
    "nvd_entry":        0.95,
    "incident_response":0.90,
    "security_blog":    0.75,
    "verified_blog":    0.75,
    "unverified_blog":  0.50,
    "stack_overflow":   0.40,
    "github_issue":     0.35,
    "community_forum":  0.30,
    "unknown":          0.30,
}


# ---------------------------------------------------------------------------
# SecRAGDefense
# ---------------------------------------------------------------------------

class SecRAGDefense:
    """
    Multi-layer defense that scores and filters retrieved documents.

    Parameters
    ----------
    embedding_model_name:
        HuggingFace model ID used for the semantic-consistency layer.
    groq_client:
        Authenticated ``groq.Groq`` instance (required for Layer 3).
    groq_model:
        Groq model identifier (e.g. ``"llama-3.1-8b-instant"``).
    """

    # Layer weights — must sum to 1.0 (verified on init)
    LAYER_WEIGHTS: dict[str, float] = {
        "source":        0.15,
        "consistency":   0.20,
        "contradiction": 0.25,
        "action":        0.25,
        "voting":        0.15,
    }

    def __init__(
        self,
        embedding_model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        groq_client: Any = None,
        groq_model: str = "llama-3.1-8b-instant",
    ) -> None:
        assert abs(sum(self.LAYER_WEIGHTS.values()) - 1.0) < 1e-3, (
            f"Layer weights must sum to 1.0, got {sum(self.LAYER_WEIGHTS.values())}"
        )

        logger.info("Loading SecRAG defence embedding model: %s", embedding_model_name)
        self.embed_model = SentenceTransformer(embedding_model_name)
        self.model_name  = embedding_model_name
        self._requires_prefix = "e5" in embedding_model_name.lower()

        self._groq_client = groq_client
        self._groq_model  = groq_model

    # ------------------------------------------------------------------
    # Groq helper
    # ------------------------------------------------------------------

    def _call_groq(self, prompt: str, max_tokens: int = 300, temperature: float = 0.1) -> str | None:
        if self._groq_client is None:
            logger.warning("Layer 3 requires a groq_client — returning None.")
            return None
        for attempt in range(_MAX_RETRIES):
            try:
                time.sleep(_REQUEST_DELAY)
                resp = self._groq_client.chat.completions.create(
                    model=self._groq_model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                return resp.choices[0].message.content.strip()
            except Exception as exc:  # noqa: BLE001
                wait = _REQUEST_DELAY * (2 ** attempt)
                logger.warning("Layer 3 retry %d/%d after %.1fs: %s", attempt + 1, _MAX_RETRIES, wait, exc)
                time.sleep(wait)
        return None

    # ------------------------------------------------------------------
    # Layer 1 — Source Reputation
    # ------------------------------------------------------------------

    def layer1_source_reputation(self, doc: dict) -> float:
        """
        Return the static reputation score for *doc*'s source type.

        Scores come from :data:`REPUTATION_SCORES`.  Unknown source types
        fall back to 0.30 (lowest trusted tier).
        """
        return REPUTATION_SCORES.get(doc.get("source_type", "unknown"), 0.30)

    # ------------------------------------------------------------------
    # Layer 2 — Semantic Consistency
    # ------------------------------------------------------------------

    def layer2_consistency(self, doc: dict, all_retrieved: list[dict]) -> float:
        """
        Mean cosine similarity between *doc* and all other retrieved documents.

        An isolated document (low average similarity) is treated as an
        anomalous outlier and assigned a low trust score.

        Returns 0.5 when the retrieved set contains only one document.
        """
        if len(all_retrieved) <= 1:
            return 0.5

        doc_emb = self.embed_model.encode(
            [doc["content"]], normalize_embeddings=True
        )[0]

        similarities = []
        for other in all_retrieved:
            if other.get("doc_id") != doc.get("doc_id"):
                other_emb = self.embed_model.encode(
                    [other["content"]], normalize_embeddings=True
                )[0]
                similarities.append(float(np.dot(doc_emb, other_emb)))

        return float(np.mean(similarities)) if similarities else 0.5

    # ------------------------------------------------------------------
    # Layer 3 — Contradiction Detection (LLM judge)
    # ------------------------------------------------------------------

    def layer3_contradiction(
        self,
        doc: dict,
        reference_doc: dict,
        cve_id: str,
    ) -> float:
        """
        LLM-as-judge comparison of *doc* against *reference_doc*.

        The judge is asked to identify direct contradictions, missing
        critical steps, severity downplaying, and risky recommendations.
        Returns a [0, 1] trust score (1.0 = full agreement with reference).

        Falls back to heuristic keyword matching if the API call fails
        or the response cannot be parsed as JSON.

        Parameters
        ----------
        doc:
            Document to evaluate.
        reference_doc:
            Highest-reputation document in the retrieved set (used as ground
            reference).
        cve_id:
            CVE identifier included in the prompt for context.

        Returns
        -------
        float
            Trust score in [0.0, 1.0].
        """
        prompt = (
            f"You are a senior security analyst evaluating remediation advice for {cve_id}.\n"
            "Compare the DOCUMENT TO EVALUATE against the REFERENCE DOCUMENT.\n\n"
            f"REFERENCE DOCUMENT (from {reference_doc.get('source_type', 'vendor_advisory')}):\n"
            f"{reference_doc['content'][:800]}\n\n"
            f"DOCUMENT TO EVALUATE (from {doc.get('source_type', 'unknown')}):\n"
            f"{doc['content'][:800]}\n\n"
            "Analyze for:\n"
            "1. DIRECT CONTRADICTIONS\n"
            "2. MISSING CRITICAL STEPS (in reference but absent from evaluated)\n"
            "3. SEVERITY DOWNPLAYING\n"
            "4. RISKY RECOMMENDATIONS\n\n"
            "Respond with ONLY valid JSON (no markdown):\n"
            '{"has_contradiction": true/false, '
            '"missing_critical_steps": ["step1"], '
            '"severity_downplayed": true/false, '
            '"trust_score": 0.0-1.0, '
            '"reasoning": "brief"}\n\n'
            "Scoring guide: "
            "1.0=complete agreement, "
            "0.7-0.9=minor omissions, "
            "0.4-0.6=significant omissions, "
            "0.1-0.3=major omissions, "
            "0.0=direct contradiction."
        )

        raw = self._call_groq(prompt, max_tokens=300, temperature=0.1)
        if not raw:
            return 0.5

        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
            cleaned = cleaned.rsplit("```", 1)[0]

        try:
            parsed = json.loads(cleaned)
            return float(parsed.get("trust_score", 0.5))
        except (json.JSONDecodeError, ValueError):
            # Keyword-based fallback
            if any(w in raw.lower() for w in ("contradiction", "missing critical", "missing step")):
                return 0.3
            return 0.7

    # ------------------------------------------------------------------
    # Layer 4 — Action Graph Completeness
    # ------------------------------------------------------------------

    def layer4_action_graph(self, doc: dict) -> float:
        """
        Return the Layer 4 action-graph completeness score for *doc*.

        Delegates to :meth:`ActionExtractor.compute_action_score`, which
        rewards action diversity and penalises false-completeness phrases.
        """
        return ActionExtractor.compute_action_score(doc["content"])

    # ------------------------------------------------------------------
    # Layer 5 — Majority-Action Voting
    # ------------------------------------------------------------------

    def layer5_voting(self, doc: dict, all_retrieved: list[dict]) -> float:
        """
        Jaccard overlap between *doc*'s action set and the union of
        action sets from all other retrieved documents.

        A document that recommends a disjoint set of actions is flagged
        as anomalous.

        Returns 0.5 when the retrieved set contains only one document.
        """
        doc_actions = ActionExtractor.extract_actions(doc["content"])
        if not doc_actions:
            return 0.5

        agreements: list[float] = []
        for other in all_retrieved:
            if other.get("doc_id") != doc.get("doc_id"):
                other_actions = ActionExtractor.extract_actions(other["content"])
                if other_actions:
                    overlap = (
                        len(doc_actions & other_actions)
                        / len(doc_actions | other_actions)
                    )
                    agreements.append(overlap)

        return float(np.mean(agreements)) if agreements else 0.5

    # ------------------------------------------------------------------
    # Composite trust score
    # ------------------------------------------------------------------

    def compute_trust_score(
        self,
        doc: dict,
        all_retrieved: list[dict],
        reference_doc: dict,
        cve_id: str,
        use_layers: list[str] | None = None,
    ) -> tuple[float, dict[str, float]]:
        """
        Compute the composite trust score for *doc* (Equation 1).

        Parameters
        ----------
        doc:
            Document to score.
        all_retrieved:
            All documents retrieved for the same query (including *doc*).
        reference_doc:
            Highest-reputation document in *all_retrieved* (used by Layer 3).
        cve_id:
            CVE identifier passed to Layer 3 for prompt context.
        use_layers:
            Ordered list of layer names to include.  Defaults to all five
            layers.  The weights are renormalised over the active subset so
            the score always lies in [0, 1].

        Returns
        -------
        (trust_score, layer_scores) : tuple[float, dict[str, float]]
            ``layer_scores`` maps each active layer name to its raw [0,1] score.
        """
        if use_layers is None:
            use_layers = list(self.LAYER_WEIGHTS.keys())

        layer_scores: dict[str, float] = {}

        if "source"        in use_layers:
            layer_scores["source"]        = self.layer1_source_reputation(doc)
        if "consistency"   in use_layers:
            layer_scores["consistency"]   = self.layer2_consistency(doc, all_retrieved)
        if "contradiction" in use_layers:
            layer_scores["contradiction"] = self.layer3_contradiction(doc, reference_doc, cve_id)
        if "action"        in use_layers:
            layer_scores["action"]        = self.layer4_action_graph(doc)
        if "voting"        in use_layers:
            layer_scores["voting"]        = self.layer5_voting(doc, all_retrieved)

        # Normalise weights over active layers (Equation 1)
        total_weight = sum(self.LAYER_WEIGHTS[l] for l in use_layers)
        trust_score  = sum(
            layer_scores.get(l, 0.5) * self.LAYER_WEIGHTS[l]
            for l in use_layers
        ) / total_weight

        return trust_score, layer_scores

    # ------------------------------------------------------------------
    # Public filter API
    # ------------------------------------------------------------------

    def filter_documents(
        self,
        retrieved_docs: list[dict],
        cve_id: str,
        threshold: float = 0.45,
        use_layers: list[str] | None = None,
    ) -> tuple[list[dict], list[dict]]:
        """
        Score and filter retrieved documents by composite trust score.

        The document with the highest source-reputation score in
        *retrieved_docs* is used as the reference for Layer 3.  Each
        document's trust score and per-layer scores are written back into
        the document dict as ``"trust_score"`` and ``"layer_scores"``.

        Parameters
        ----------
        retrieved_docs:
            Output of :meth:`RAGPipeline.retrieve`.
        cve_id:
            CVE identifier for Layer 3 prompt context.
        threshold:
            Documents with trust score below this value are removed.
            Default 0.45 (knee-point from §5.3 threshold sweep).
        use_layers:
            Active layer subset; defaults to all five layers.

        Returns
        -------
        (filtered, removed) : tuple[list[dict], list[dict]]
            ``filtered`` — documents whose trust score ≥ threshold.
            ``removed``  — documents whose trust score < threshold.
        """
        if not retrieved_docs:
            return retrieved_docs, []

        # Select reference document (highest source reputation)
        reference_doc = max(
            retrieved_docs,
            key=lambda d: REPUTATION_SCORES.get(d.get("source_type", "unknown"), 0.30),
        )

        filtered: list[dict] = []
        removed:  list[dict] = []

        for doc in retrieved_docs:
            trust_score, layer_scores = self.compute_trust_score(
                doc, retrieved_docs, reference_doc, cve_id, use_layers
            )
            # Write scores back for downstream analysis
            doc["trust_score"]   = trust_score
            doc["layer_scores"]  = layer_scores

            if trust_score >= threshold:
                filtered.append(doc)
            else:
                removed.append(doc)

        return filtered, removed

    # ------------------------------------------------------------------
    # Memory management
    # ------------------------------------------------------------------

    def unload(self) -> None:
        """Release the embedding model from memory."""
        del self.embed_model
        self.embed_model = None
        gc.collect()
        logger.info("SecRAGDefense unloaded.")

    def __repr__(self) -> str:
        return (
            f"SecRAGDefense(model={self.model_name!r}, "
            f"weights={self.LAYER_WEIGHTS})"
        )
