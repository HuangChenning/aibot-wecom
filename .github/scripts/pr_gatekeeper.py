from __future__ import annotations

import json
from dataclasses import dataclass


ALLOWED_VERDICTS = frozenset({"MERGEABLE", "NOT_MERGEABLE", "INCONCLUSIVE"})
REQUIRED_CHECKS = frozenset({"ruff", "pytest"})


@dataclass(frozen=True)
class Verdict:
    name: str
    reason: str = ""


@dataclass(frozen=True)
class ModelVerdict:
    name: str
    acceptance_criteria: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    reason: str = ""


def deterministic_verdict(
    initial_sha: str,
    current_sha: str,
    exit_codes: dict[str, int],
    *,
    api_key_present: bool,
) -> Verdict:
    if initial_sha != current_sha:
        return Verdict("NOT_MERGEABLE", "PR head changed during verification.")
    if not api_key_present:
        return Verdict("INCONCLUSIVE", "MINIMAX_API_KEY is unavailable.")
    if not REQUIRED_CHECKS.issubset(exit_codes):
        return Verdict("INCONCLUSIVE", "Verification exit-code evidence is incomplete.")
    if any(exit_codes[check] != 0 for check in REQUIRED_CHECKS):
        return Verdict("NOT_MERGEABLE", "Required verification command failed.")
    return Verdict("MERGEABLE")


def parse_model_verdict(body: str) -> ModelVerdict:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return ModelVerdict("INCONCLUSIVE", reason="Model response is not valid JSON.")

    if not isinstance(payload, dict) or set(payload) != {
        "verdict",
        "acceptance_criteria",
        "observations",
    }:
        return ModelVerdict("INCONCLUSIVE", reason="Model response has an invalid schema.")

    name = payload["verdict"]
    criteria = payload["acceptance_criteria"]
    observations = payload["observations"]
    if (
        name not in ALLOWED_VERDICTS
        or not isinstance(criteria, list)
        or not isinstance(observations, list)
        or not all(isinstance(item, str) for item in criteria + observations)
    ):
        return ModelVerdict("INCONCLUSIVE", reason="Model response has invalid values.")

    return ModelVerdict(name, tuple(criteria), tuple(observations))
