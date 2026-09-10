from __future__ import annotations

import sys
import tempfile
import unittest
import json
from subprocess import CalledProcessError
from pathlib import Path
from urllib.error import URLError


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pr_gatekeeper import (
    evaluate_model,
    make_model_request,
    parse_model_verdict,
    publish_report,
    run_gatekeeper,
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

    def test_markdown_fenced_model_json_is_accepted(self) -> None:
        payload = (
            '{"verdict":"MERGEABLE","acceptance_criteria":[],'
            '"observations":[]}'
        )
        body = f"```json\n{payload}\n```"

        verdict = parse_model_verdict(body)

        self.assertEqual("MERGEABLE", verdict.name)

    def test_prose_wrapped_model_json_is_accepted(self) -> None:
        body = (
            "Here is the review.\n"
            '{"verdict":"MERGEABLE","acceptance_criteria":["ruff"],'
            '"observations":[]}\n'
            "Thanks."
        )

        verdict = parse_model_verdict(body)

        self.assertEqual("MERGEABLE", verdict.name)
        self.assertEqual(("ruff",), verdict.acceptance_criteria)

    def test_extra_model_keys_are_ignored(self) -> None:
        body = (
            '{"verdict":"MERGEABLE","acceptance_criteria":[],'
            '"observations":[],"reason":"looks good","score":1}'
        )

        verdict = parse_model_verdict(body)

        self.assertEqual("MERGEABLE", verdict.name)

    def test_nested_model_object_is_accepted(self) -> None:
        body = (
            '{"review":{"verdict":"MERGEABLE","acceptance_criteria":["pytest"],'
            '"observations":[]}}'
        )

        verdict = parse_model_verdict(body)

        self.assertEqual("MERGEABLE", verdict.name)
        self.assertEqual(("pytest",), verdict.acceptance_criteria)

    def test_empty_optional_model_configuration_uses_safe_defaults(self) -> None:
        request = make_model_request("", "", "secret-value", "prompt")
        payload = json.loads(request.data.decode("utf-8"))

        self.assertEqual("https://api.minimax.chat/v1/chat/completions", request.full_url)
        self.assertEqual("MiniMax-Text-01", payload["model"])

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


class EntrypointTests(unittest.TestCase):
    def test_entrypoint_writes_mergeable_verdict_for_current_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            self._write_evidence(evidence, {"ruff": 0, "pytest": 0})

            code = run_gatekeeper(
                self._environment("head"),
                evidence,
                evidence / "summary.md",
                runner=self._gh_returning("head"),
                opener=self._mergeable_minimax,
            )

            self.assertEqual(0, code)
            verdict = json.loads((evidence / "verdict.json").read_text())
            self.assertEqual("MERGEABLE", verdict["verdict"])

    def test_entrypoint_blocks_when_head_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            self._write_evidence(evidence, {"ruff": 0, "pytest": 0})

            code = run_gatekeeper(
                self._environment("before"),
                evidence,
                evidence / "summary.md",
                runner=self._gh_returning("after"),
                opener=self._mergeable_minimax,
            )

            self.assertEqual(1, code)
            verdict = json.loads((evidence / "verdict.json").read_text())
            self.assertEqual("NOT_MERGEABLE", verdict["verdict"])

    def test_entrypoint_blocks_malformed_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            self._write_evidence(evidence, {"ruff": 0, "pytest": 0})
            (evidence / "pr_meta.json").write_text("[]")

            code = run_gatekeeper(
                self._environment("head"),
                evidence,
                evidence / "summary.md",
                runner=self._gh_returning("head"),
                opener=self._mergeable_minimax,
            )

            self.assertEqual(1, code)
            verdict = json.loads((evidence / "verdict.json").read_text())
            self.assertEqual("INCONCLUSIVE", verdict["verdict"])

    @staticmethod
    def _write_evidence(evidence: Path, exit_codes: dict[str, int]) -> None:
        (evidence / "exit-codes.json").write_text(json.dumps(exit_codes))
        (evidence / "ruff.log").write_text("ruff passed")
        (evidence / "pytest.log").write_text("pytest passed")
        (evidence / "pr_meta.json").write_text('{"title":"title","body":"body"}')
        (evidence / "pr_diff.patch").write_text("diff")

    @staticmethod
    def _environment(initial_sha: str) -> dict[str, str]:
        return {
            "INITIAL_SHA": initial_sha,
            "PR_NUMBER": "42",
            "MINIMAX_API_KEY": "secret-value",
            "MINIMAX_BASE_URL": "https://example.invalid/v1",
            "MINIMAX_MODEL": "model",
        }

    @staticmethod
    def _gh_returning(head: str):
        class Result:
            def __init__(self, stdout: str) -> None:
                self.stdout = stdout

        def runner(args: list[str], **_kwargs: object) -> Result:
            if "view" in args:
                return Result(head)
            return Result("")

        return runner

    @staticmethod
    def _mergeable_minimax(*_args: object, **_kwargs: object) -> object:
        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"choices":[{"message":{"content":"{\\"verdict\\":\\"MERGEABLE\\",\\"acceptance_criteria\\":[],\\"observations\\":[]}"}}]}'

        return Response()


class WorkflowShapeTests(unittest.TestCase):
    def test_workflow_never_exposes_minimax_key_to_pr_validation(self) -> None:
        workflow = Path(".github/workflows/pr-gatekeeper.yml").read_text(
            encoding="utf-8"
        )
        validation = workflow.split("Run trusted gatekeeper", 1)[0]

        self.assertNotIn("MINIMAX_API_KEY", validation)
        self.assertNotIn("pull_request_target", workflow)

    def test_workflow_checks_out_trusted_base_script(self) -> None:
        workflow = Path(".github/workflows/pr-gatekeeper.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", workflow)
        self.assertIn("path: gatekeeper", workflow)


class DocumentationTests(unittest.TestCase):
    def test_readme_mentions_required_secret_and_branch_protection(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn("MINIMAX_API_KEY", readme)
        self.assertIn("Gatekeeper Verification", readme)
