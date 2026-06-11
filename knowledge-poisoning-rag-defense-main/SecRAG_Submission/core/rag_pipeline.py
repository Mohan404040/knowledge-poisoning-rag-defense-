"""
rag_pipeline.py — FAISS-Based RAG Retrieval Pipeline
=====================================================
SecRAG: Retrieval-Augmented Generation Security Framework
IEEE S&P Submission

Implements a dense retrieval pipeline over security document corpora
using FAISS flat inner-product indices. Supports arbitrary
SentenceTransformer embedding models to enable the multi-embedding
ablation study (Experiment 02).

All embedding vectors are L2-normalised before indexing so that inner
product equals cosine similarity.

Typical usage::

    from core.rag_pipeline import RAGPipeline

    rag = RAGPipeline("sentence-transformers/all-MiniLM-L6-v2")
    rag.build_index(documents)          # list of dicts with "content" key
    results = rag.retrieve(query, top_k=3)
    rag.unload()
"""

from __future__ import annotations

import gc
import logging
from typing import Any

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

# Models validated for SecRAG experiments
SUPPORTED_MODELS: dict[str, str] = {
    "MiniLM":    "sentence-transformers/all-MiniLM-L6-v2",
    "BGE-small": "BAAI/bge-small-en-v1.5",
    "E5-small":  "intfloat/e5-small-v2",
}

# E5 models require a task prefix on query strings
_E5_QUERY_PREFIX = "query: "


class RAGPipeline:
    """
    Dense retrieval pipeline backed by FAISS and SentenceTransformers.

    Parameters
    ----------
    model_name:
        HuggingFace model ID or short alias from :data:`SUPPORTED_MODELS`.
    """

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> None:
        # Resolve short alias if provided
        resolved = SUPPORTED_MODELS.get(model_name, model_name)
        logger.info("Loading embedding model: %s", resolved)

        self.model_name: str = resolved
        self.model: SentenceTransformer = SentenceTransformer(resolved)
        self.index: faiss.Index | None = None
        self.documents: list[dict] = []
        self.embeddings: np.ndarray | None = None
        self._requires_prefix: bool = "e5" in resolved.lower()

        logger.info(
            "Model loaded — dim=%d, E5-prefix=%s",
            self.model.get_sentence_embedding_dimension(),
            self._requires_prefix,
        )

    # ------------------------------------------------------------------
    # Index construction
    # ------------------------------------------------------------------

    def build_index(self, documents: list[dict]) -> None:
        """
        Encode *documents* and build a FAISS flat inner-product index.

        Parameters
        ----------
        documents:
            List of document dicts, each containing at minimum a ``"content"``
            key with the document text string.
        """
        self.documents = documents
        contents = [d["content"] for d in documents]

        logger.info("Encoding %d documents with %s…", len(contents), self.model_name)
        self.embeddings = self.model.encode(
            contents,
            show_progress_bar=True,
            normalize_embeddings=True,
            batch_size=64,
        )

        dim = self.embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dim)
        self.index.add(self.embeddings.astype(np.float32))
        logger.info("FAISS index ready — %d vectors, dim=%d", self.index.ntotal, dim)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def retrieve(self, query: str, top_k: int = 3) -> list[dict]:
        """
        Retrieve the *top_k* most similar documents to *query*.

        For E5 models the query is automatically prefixed with
        ``"query: "`` per the model's intended usage.

        Parameters
        ----------
        query:
            Natural-language query string.
        top_k:
            Number of results to return.

        Returns
        -------
        list of dict
            Each element is a copy of the corresponding document dict with two
            additional keys: ``retrieval_score`` (cosine similarity) and
            ``retrieval_rank`` (1-indexed).
        """
        if self.index is None:
            raise RuntimeError("Index not built. Call build_index() first.")

        if self._requires_prefix and not query.startswith(_E5_QUERY_PREFIX):
            query = _E5_QUERY_PREFIX + query

        q_emb = self.model.encode(
            [query], normalize_embeddings=True
        ).astype(np.float32)

        scores, indices = self.index.search(q_emb, top_k)

        results: list[dict] = []
        for rank, (score, idx) in enumerate(zip(scores[0], indices[0]), start=1):
            if idx < len(self.documents):
                doc = self.documents[idx].copy()
                doc["retrieval_score"] = float(score)
                doc["retrieval_rank"] = rank
                results.append(doc)

        return results

    # ------------------------------------------------------------------
    # Embedding utilities
    # ------------------------------------------------------------------

    def get_embedding(self, text: str) -> np.ndarray:
        """
        Return the L2-normalised embedding vector for *text*.

        Used by the embedding-similarity analysis (Experiment 04).
        """
        return self.model.encode([text], normalize_embeddings=True)[0]

    def get_embeddings_batch(self, texts: list[str]) -> np.ndarray:
        """Return normalised embeddings for a batch of texts."""
        return self.model.encode(texts, normalize_embeddings=True, batch_size=64)

    # ------------------------------------------------------------------
    # Memory management
    # ------------------------------------------------------------------

    def unload(self) -> None:
        """
        Release the embedding model and FAISS index from memory.

        Call this between embedding model switches in the multi-embedding
        experiment to avoid OOM errors on constrained Kaggle kernels.
        """
        del self.model
        del self.index
        del self.embeddings
        self.model = None
        self.index = None
        self.embeddings = None
        gc.collect()
        logger.info("RAGPipeline unloaded.")

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        """True if the index has been built and is ready for retrieval."""
        return self.index is not None and len(self.documents) > 0

    @property
    def embedding_dim(self) -> int | None:
        """Embedding dimensionality, or None if model not loaded."""
        if self.model is not None:
            return self.model.get_sentence_embedding_dimension()
        return None

    def __repr__(self) -> str:
        return (
            f"RAGPipeline(model={self.model_name!r}, "
            f"indexed={self.index.ntotal if self.index else 0} docs)"
        )
