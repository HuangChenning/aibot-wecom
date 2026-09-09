from __future__ import annotations

import sys
import tempfile
import unittest
from subprocess import CalledProcessError
from pathlib import Path
from urllib.error import URLError


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pr_gatekeeper import (
    evaluate_model,
    make_model_request,
    parse_model_verdict,
    publish_report,
    truncate_text,
)
from pr_gatekeeper import deterministic_verdict


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

    def test_api_error_becomes_inconclusive_without_echoing_secret(self) -> None:
        request = make_model_request(
            "https://example.invalid/v1", "model", "secret-value", "prompt"
        )

        def raise_url_error(*_args: object, **_kwargs: object) -> object:
            raise URLError("secret-value")

        verdict = evaluate_model(request, opener=raise_url_error)

        self.assertEqual("INCONCLUSIVE", verdict.name)
        self.assertNotIn("secret-value", verdict.reason)

    def test_valid_model_json_is_accepted(self) -> None:
        request = make_model_request(
            "https://example.invalid/v1", "model", "secret-value", "prompt"
        )

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"choices":[{"message":{"content":"{\\"verdict\\":\\"MERGEABLE\\",\\"acceptance_criteria\\":[],\\"observations\\":[]}"}}]}'

        verdict = evaluate_model(request, opener=lambda *_args, **_kwargs: Response())

        self.assertEqual("MERGEABLE", verdict.name)

    def test_truncate_text_marks_omitted_characters(self) -> None:
        self.assertEqual("abc... [2 characters omitted]", truncate_text("abcde", 3))


class ReportingTests(unittest.TestCase):
    def test_comment_failure_keeps_summary_report(self) -> None:
        with self.subTest("comment failure"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                report = root / "report.md"
                summary = root / "summary.md"
                report.write_text("report", encoding="utf-8")

                def failing_runner(*_args: object, **_kwargs: object) -> object:
                    raise OSError("no token")

                status = publish_report(report, summary, "42", runner=failing_runner)

                self.assertEqual("comment_failed", status)
                self.assertEqual("report", summary.read_text(encoding="utf-8"))

    def test_nonzero_comment_command_keeps_summary_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.md"
            summary = root / "summary.md"
            report.write_text("report", encoding="utf-8")

            def nonzero_runner(*_args: object, **_kwargs: object) -> object:
                raise CalledProcessError(1, "gh")

            status = publish_report(report, summary, "42", runner=nonzero_runner)

            self.assertEqual("comment_failed", status)
            self.assertEqual("report", summary.read_text(encoding="utf-8"))
