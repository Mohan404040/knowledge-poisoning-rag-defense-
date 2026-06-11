# SecRAG: Retrieval-Augmented Generation Security Framework
### IEEE S&P Submission — Code Artifact

---

## Repository Structure

```
SecRAG_Submission/
│
├── core/                        # Framework core modules
│   ├── data_loader.py           # Corpus loader & validation utilities
│   ├── rag_pipeline.py          # FAISS-based RAG retrieval pipeline
│   ├── metrics.py               # Evaluation metrics, LLM-as-Judge, response generator
│   ├── cves.py                  # CVE metadata & ground-truth action database
│   ├── poison_generator.py      # Adversarial document generation module
│   └── action_extractor.py      # Regex-based remediation action extractor
│
├── defense/                     # Defense system
│   └── secrag_defense.py        # SecRAG multi-layer defense system
│
├── experiments/                 # Main experimental scripts (§5 of paper)
│   ├── 02_multi_embedding.py    # Multi-embedding model ablation study
│   ├── 03_vocabulary_overlap.py # Vocabulary overlap analysis
│   ├── 04_embedding_similarity.py # Embedding similarity analysis
│   ├── 06_adaptive_attacker.py  # Adaptive attacker evaluation
│   └── 07_incomplete_context_rate.py # Incomplete context rate analysis
│
└── analysis/                    # Deep-dive analysis scripts
    ├── 05_defense_embeddings.py # Defense generalisation across embedding models
    ├── 08_conditional_asr_deep.py # Conditional ASR deep analysis & majority-vote baseline
    └── 09_case_studies.py       # Detailed case studies
```

---

## Module Descriptions

### `core/`
These are the shared framework modules imported by all experiment scripts. They must be available on the Python path before running any experiment.

| File | Purpose |
|------|---------|
| `data_loader.py` | Loads and validates the SecRAG CVE corpus |
| `rag_pipeline.py` | FAISS index construction and top-k retrieval |
| `metrics.py` | ASR computation, LLM-as-Judge scoring, response generation |
| `cves.py` | Ground-truth CVE records and remediation action labels |
| `poison_generator.py` | Generates adversarial (poisoned) documents per attack type |
| `action_extractor.py` | Extracts and scores remediation actions from free-form text |

### `defense/`
| File | Purpose |
|------|---------|
| `secrag_defense.py` | Multi-layer defense: source trust, semantic anomaly detection, action-graph scoring |

### `experiments/`
Core experiments demonstrating the poison-retrieval vulnerability and attack generalisability (referenced in §5 of the paper).

| File | Paper Section |
|------|--------------|
| `02_multi_embedding.py` | §5.2 — Model-agnostic vulnerability across embedding architectures |
| `03_vocabulary_overlap.py` | §5.3 — Lexical analysis of poisoned vs. benign documents |
| `04_embedding_similarity.py` | §5.4 — Embedding-space proximity of adversarial documents |
| `06_adaptive_attacker.py` | §5.6 — Adaptive attacker aware of the defense pipeline |
| `07_incomplete_context_rate.py` | §5.7 — Rate of incomplete/missing remediation context |

### `analysis/`
Deeper analysis scripts supporting the discussion and ablation sections.

| File | Paper Section |
|------|--------------|
| `05_defense_embeddings.py` | §6.1 — Defense effectiveness across embedding models |
| `08_conditional_asr_deep.py` | §6.2 — Conditional ASR breakdown & majority-vote baseline |
| `09_case_studies.py` | §6.3 — End-to-end qualitative case studies |

---

## Setup & Usage

### Requirements
```bash
pip install sentence-transformers faiss-cpu openai pandas numpy tqdm
```

### Running Experiments
All experiment scripts follow the same CLI pattern:
```bash
python experiments/<script>.py \
    --data-dir ./data \
    --output-dir ./results
```

Results are saved as JSON files to `--output-dir` using the script's filename as prefix (e.g., `results/02_multi_embedding.json`).

### Recommended Execution Order
1. Verify `core/` modules are importable from your working directory
2. Run experiments `02` → `07` in order (each is independent)
3. Run analysis scripts `05`, `08`, `09` after experiments complete
4. Run `defense/secrag_defense.py` to evaluate the full defense pipeline

---

## Citation
If you use this code, please cite our IEEE S&P submission (details to be added upon acceptance).
