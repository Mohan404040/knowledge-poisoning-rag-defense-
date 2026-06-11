# # SecRAG: Knowledge Poisoning Defense for Cybersecurity RAG Systems

SecRAG is a cybersecurity-focused Retrieval-Augmented Generation (RAG) security framework designed to detect and mitigate knowledge-poisoning attacks that target external knowledge sources used by Large Language Models (LLMs).

Modern RAG systems improve LLM responses by retrieving information from external document repositories. However, attackers can manipulate these repositories by injecting malicious, misleading, or poisoned content, causing the model to generate incorrect or unsafe outputs. SecRAG addresses this challenge through a multi-layer defense architecture that validates retrieved information before it influences the final response.

The framework introduces an Action-Graph Completeness Scoring mechanism combined with retrieval validation, anomaly detection, and consistency analysis to identify suspicious knowledge patterns. Extensive evaluation was performed using real-world cybersecurity datasets, including Common Vulnerabilities and Exposures (CVEs), synthesized attack documents, and multiple embedding architectures.

## Key Features

* Detection of knowledge-poisoning attacks in RAG pipelines.
* Multi-layer security validation framework.
* Action-Graph Completeness Scoring for response verification.
* Evaluation across multiple embedding models and attack scenarios.
* Cybersecurity-focused benchmark using real-world CVE data.

## Technologies Used

* Python
* Large Language Models (LLMs)
* Retrieval-Augmented Generation (RAG)
* Vector Databases
* Information Retrieval
* Machine Learning
* Cybersecurity Analytics

## Results

* Reduced attack success rate from 78.4% to 13.0%.
* Achieved an F1-score of 0.89 for attack detection.
* Demonstrated robustness against multiple knowledge-poisoning strategies and adaptive attackers.

## Research Impact

This project explores the intersection of Artificial Intelligence, Cybersecurity, and Trustworthy LLM Systems. The work contributes toward building secure and reliable RAG-based applications capable of operating in adversarial environments.

**Status:** Research Manuscript Completed and Ready for Journal/Conference Submission.
