from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fitz

from cyber_os import web_assessment_report
from cyber_os.web_assessment_report import write_web_assessment_pdf


class WebAssessmentReportTests(unittest.TestCase):
    def test_interpretation_is_restrained_and_unwraps_serialized_plugin_results(self) -> None:
        recorded_steps = [
            {
                "tool": "web_security_headers",
                "success": True,
                "output": json.dumps({
                    "success": True,
                    "output": {
                        "missing_security_headers": ["Content-Security-Policy", "X-Frame-Options"],
                        "tls_verification": "verified",
                        "security_headers": {
                            "Content-Security-Policy": "MISSING",
                            "X-Frame-Options": "MISSING",
                        },
                    },
                }),
            },
            {
                "tool": "xss_scanner",
                "success": True,
                "output": json.dumps({
                    "success": True,
                    "output": json.dumps({"reflected": True, "status": 200}),
                }),
            },
            {
                "tool": "sqli_scanner",
                "success": True,
                "output": json.dumps({
                    "success": True,
                    "output": {"possible_sqli": True, "response_length_delta": 84, "param": "id"},
                }),
            },
            {
                "tool": "web_tech_fingerprint",
                "success": True,
                "output": json.dumps({
                    "success": True,
                    "output": {"detected": True, "technologies": [{"name": "ExampleCMS", "category": "cms"}]},
                }),
            },
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = write_web_assessment_pdf(
                "https://example.test/app", recorded_steps, output_dir=Path(temp_dir)
            )
            with fitz.open(artifact["path"]) as pdf:
                text = "\n".join(page.get_text() for page in pdf)

        lowered = text.lower()
        self.assertIn("evidence interpretation", lowered)
        self.assertIn("content-security-policy", lowered)
        self.assertIn("x-frame-options", lowered)
        self.assertIn("configuration observation", lowered)
        self.assertIn("tls certificate validation succeeded", lowered)
        self.assertIn("candidate", lowered)
        self.assertIn("response-length signal", lowered)
        self.assertIn("84", text)
        self.assertIn("examplecms", lowered)
        self.assertIn("inventory", lowered)
        self.assertIn("no csrf-specific check", lowered)
        self.assertNotIn("confirmed xss", lowered)
        self.assertNotIn("confirmed sqli", lowered)

    def test_nested_plugin_failure_overrides_outer_success_for_interpretation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = write_web_assessment_pdf(
                "https://example.test/",
                [{
                    "tool": "xss_scanner",
                    "success": True,
                    "output": json.dumps({
                        "success": False,
                        "output": {"reflected": True},
                        "error": "probe did not complete",
                    }),
                }],
                output_dir=Path(temp_dir),
            )
            with fitz.open(artifact["path"]) as pdf:
                text = "\n".join(page.get_text() for page in pdf)

        self.assertIn("xss_scanner - FAILED", text)
        self.assertNotIn("candidate reflection observation", text.lower())

    def test_report_is_readable_and_contains_recorded_outcomes_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = write_web_assessment_pdf(
                "https://example.test/login",
                [
                    {
                        "tool": "web_security_headers",
                        "success": True,
                        "output": "Content-Security-Policy: default-src 'self'",
                    },
                    {
                        "tool": "xss_scanner",
                        "success": False,
                        "error": "Connection timed out",
                    },
                ],
                output_dir=Path(temp_dir),
            )

            self.assertTrue(Path(artifact["path"]).is_file())
            self.assertRegex(artifact["report_id"], r"^[0-9a-f]{32}$")
            self.assertEqual(
                Path(artifact["path"]).name,
                f"web-assessment-{artifact['report_id']}.pdf",
            )
            self.assertTrue(Path(artifact["path"]).read_bytes().startswith(b"%PDF-"))

            with fitz.open(artifact["path"]) as pdf:
                self.assertGreaterEqual(pdf.page_count, 1)
                text = "\n".join(page.get_text() for page in pdf)

            self.assertIn("https://example.test/login", text)
            self.assertIn("Executive summary", text)
            self.assertIn("No confirmed vulnerabilities were established", text)
            self.assertIn("did not crawl linked pages", text)
            self.assertIn("Recommended follow-up", text)
            self.assertIn("web_security_headers", text)
            self.assertIn("COMPLETED", text)
            self.assertIn("Content-Security-Policy", text)
            self.assertIn("xss_scanner", text)
            self.assertIn("FAILED", text)
            self.assertIn("Connection timed out", text)
            self.assertIn("No findings are inferred", text)
            self.assertIn("No CSRF-specific check", text)
            self.assertNotIn("confirmed vulnerability", text.lower())

    def test_unknown_status_is_not_reported_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = write_web_assessment_pdf(
                "http://example.test/",
                [{"tool": "custom_check", "output": "Unstructured output only."}],
                output_dir=Path(temp_dir),
            )
            with fitz.open(artifact["path"]) as pdf:
                text = "\n".join(page.get_text() for page in pdf)

            self.assertIn("custom_check", text)
            self.assertIn("UNKNOWN", text)
            self.assertIn("Unstructured output only.", text)
            self.assertNotIn("custom_check: COMPLETED", text)

    def test_structured_page_text_is_rendered_with_real_line_breaks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = write_web_assessment_pdf(
                "https://example.test/",
                [{
                    "tool": "open_url",
                    "success": True,
                    "output": json.dumps({
                        "success": True,
                        "output": {
                            "title": "Example",
                            "content": "\nHome\nSecurity\n",
                        },
                    }),
                }],
                output_dir=Path(temp_dir),
            )
            with fitz.open(artifact["path"]) as pdf:
                text = "\n".join(page.get_text() for page in pdf)

        self.assertIn("Home", text)
        self.assertIn("Security", text)
        self.assertNotIn(r"\nHome", text)

    def test_evidence_formatter_collapses_html_extraction_whitespace(self) -> None:
        formatted = web_assessment_report._format_evidence({
            "content": "\t\n\t\nHome\n\n\nSecurity\n",
        })
        no_empty_values = web_assessment_report._format_evidence({"error": ""})

        self.assertRegex(formatted, r"Home\n\s*\n\s+Security")
        self.assertNotIn("\n  \n  \n", formatted)
        self.assertNotIn("error:", no_empty_values)

    def test_report_identifier_and_path_do_not_derive_from_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = write_web_assessment_pdf(
                "https://example.test/../../unexpected.pdf",
                [],
                output_dir=Path(temp_dir),
            )
            output_path = Path(artifact["path"]).resolve()
            self.assertEqual(output_path.parent, Path(temp_dir).resolve())
            self.assertNotRegex(artifact["report_id"], r"[./\\]")
            self.assertRegex(artifact["report_id"], r"^[0-9a-f]{32}$")

    def test_report_path_helper_accepts_only_existing_generated_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = write_web_assessment_pdf(
                "https://example.test/",
                [],
                output_dir=Path(temp_dir),
            )
            with mock.patch.object(
                web_assessment_report, "_default_report_dir", return_value=Path(temp_dir)
            ):
                self.assertEqual(
                    web_assessment_report.get_web_assessment_report_path(
                        artifact["report_id"]
                    ),
                    Path(artifact["path"]).resolve(),
                )
                with self.assertRaises(ValueError):
                    web_assessment_report.get_web_assessment_report_path("../audit")
                with self.assertRaises(FileNotFoundError):
                    web_assessment_report.get_web_assessment_report_path("0" * 32)

    def test_default_output_is_the_requested_pdf_artifact_directory(self) -> None:
        self.assertEqual(
            web_assessment_report._default_report_dir(),
            Path(__file__).resolve().parents[1] / "output" / "pdf",
        )


if __name__ == "__main__":
    unittest.main()
