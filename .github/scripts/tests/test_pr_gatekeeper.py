from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pr_gatekeeper import deterministic_verdict, parse_model_verdict


class DeterministicVerdictTests(unittest.TestCase):
    def test_missing_api_key_is_inconclusive(self) -> None:
        verdict = deterministic_verdict(
            "a", "a", {"ruff": 0, "pytest": 0}, api_key_present=False
        )

        self.assertEqual("INCONCLUSIVE", verdict.name)

    def test_changed_head_is_not_mergeable(self) -> None:
        verdict = deterministic_verdict(
            "a", "b", {"ruff": 0, "pytest": 0}, api_key_present=True
        )

        self.assertEqual("NOT_MERGEABLE", verdict.name)


class ModelVerdictTests(unittest.TestCase):
    def test_invalid_model_json_is_inconclusive(self) -> None:
        verdict = parse_model_verdict("MERGEABLE")

        self.assertEqual("INCONCLUSIVE", verdict.name)
