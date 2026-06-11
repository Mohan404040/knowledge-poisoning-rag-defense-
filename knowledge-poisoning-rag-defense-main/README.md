# knowledge-poisoning-rag-defense
Knowledge poisoning attacks and Action-Graph completeness defense for cybersecurity RAG systems — benchmark of 80 CVEs, four attack taxonomies, five-layer trust-scoring pipeline.
# Knowledge Poisoning Attacks and Action-Graph Defense in Cybersecurity RAG Systems

Manuscript under review — Applied Intelligence (Springer)**  
Companion code for: "Knowledge Poisoning Attacks and Action-Graph Defense in Retrieval-Augmented Systems for Cybersecurity"*

Overview

Retrieval-Augmented Generation (RAG) systems are increasingly used in cybersecurity workflows to deliver on-demand vulnerability remediation guidance. This repository provides the full experimental pipeline accompanying our paper, which:

- Introduces a **taxonomy of four knowledge poisoning attack modalities** against cybersecurity RAG systems
- Identifies the **Partial-Fix attack** as the most dangerous variant — achieving a 96.4% conditional attack success rate by providing correct but *incomplete* remediation advice that neither the generator nor a human reviewer is likely to question
- Proposes a **five-layer Action-Graph defense architecture** that reduces mean attack success rate from **78.4% → 13.0%** (detection F1 = 0.89) across three embedding architectures
- Introduces the **Adversarial Retrieval Susceptibility (ARS)** metric, revealing that higher benchmark-ranked embedding models are *more* adversarially vulnerable — not less

All experiments were run on free-tier Kaggle infrastructure (2 CPU cores, 13 GB RAM, no GPU), demonstrating that both the attack and defense are practically accessible without specialized hardware.


Repository Structure
├── core/
│   ├── cves.py               # 80 real-world CVEs with ground-truth action sequences
│   ├── data_loader.py        # Corpus loader and validation
│   ├── rag_pipeline.py       # FAISS-based top-k retrieval pipeline
│   ├── poison_generator.py   # Generates clean, poisoned, and adaptive documents via Groq API
│   ├── action_extractor.py   # Regex-based remediation action extractor (7 action classes)
│   └── metrics.py            # ASR / CASR / RR metrics + LLM-as-Judge evaluation
│
├── defense/
│   └── secrag_defense.py     # Five-layer trust-scoring defense framework
│
├── experiments/
│   ├── 02_multi_embedding.py          # Attack success across MiniLM / BGE-small / E5-small
│   ├── 03_vocabulary_overlap.py       # Lexical analysis: poisoned vs. clean documents
│   ├── 04_embedding_similarity.py     # Embedding-space proximity of adversarial documents
│   ├── 06_adaptive_attacker.py        # White-box adaptive adversary evaluation
│   └── 07_incomplete_context_rate.py  # Incomplete context retrieval rate analysis
│
└── analysis/
├── 05_defense_embeddings.py       # Defense generalization across embedding models
├── 08_conditional_asr_deep.py     # Conditional ASR breakdown + majority-vote baseline
└── 09_case_studies.py             # End-to-end qualitative case studies
---
The Partial-Fix attack is uniquely dangerous because it contains **no false claims** — only omissions. All existing defenses (TrustRAG, InstructRAG, perplexity filtering, certifiable RAG) achieve zero or near-zero recall against it.

