"""Local, fail-closed LLM triage over an analysis bundle (D22).

HATCHERY's triage layer is deliberately *not* a chatbot bolted onto JSON. It is
a contract:

* the model runs **locally** (Ollama on loopback) by default, and a
  ``:cloud`` model — which would ship sample-derived text off the machine — is
  refused unless explicitly allowed;
* the model's output must satisfy a fixed JSON schema, enforced twice (Ollama's
  structured-output ``format`` and HATCHERY's own validator), because the
  validator is what HATCHERY trusts, not the runtime;
* every claim must cite an evidence id that actually exists in the run, or the
  claim is dropped; a verdict left with no grounded finding is **INCONCLUSIVE**,
  never a verdict;
* sample-derived text is wrapped in an explicit untrusted-data boundary and the
  model is told never to follow instructions inside it — malware strings are
  adversarial input to an LLM (Microsoft's Project Ire documented exactly this).

Nothing in this package treats a model output as ground truth. A triage result
is advisory, is labelled as model-generated, and never replaces the engine's own
findings.
"""

from __future__ import annotations

from engine.triage.client import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL_PREFERENCE,
    OllamaClient,
    OllamaError,
    is_local_model,
    supports_completion,
)
from engine.triage.contract import (
    PROMPT_CONTRACT_VERSION,
    RESPONSE_SCHEMA,
    SYSTEM_PROMPT,
    contract_hash,
)
from engine.triage.context import Evidence, EvidenceEntry, build_evidence
from engine.triage.triage import TRIAGE_STATE_INCONCLUSIVE, TriageConfig, run_triage

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL_PREFERENCE",
    "Evidence",
    "EvidenceEntry",
    "OllamaClient",
    "OllamaError",
    "PROMPT_CONTRACT_VERSION",
    "RESPONSE_SCHEMA",
    "SYSTEM_PROMPT",
    "TRIAGE_STATE_INCONCLUSIVE",
    "TriageConfig",
    "build_evidence",
    "contract_hash",
    "is_local_model",
    "run_triage",
    "supports_completion",
]
