"""sentinel-triage: SOC alert-fatigue reduction prototype.

Pipeline: log ingestion -> OpenSearch storage -> entity/time correlation ->
Sigma/MITRE detection -> LLM triage (with citation grounding) -> analyst
review queue, plus an evaluation harness for precision/recall/FPR.
"""

__version__ = "0.1.0"
