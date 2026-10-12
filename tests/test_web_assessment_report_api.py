from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from cyber_os.web_assessment_report import write_web_assessment_pdf
from ui import api_server


class WebAssessmentReportApiTests(unittest.TestCase):
    def test_download_route_serves_only_generated_pdf_as_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = write_web_assessment_pdf(
                "https://example.test/",
                [{"tool": "open_url", "success": True, "output": "Test page"}],
                output_dir=Path(temp_dir),
            )
            with patch(
                "cyber_os.web_assessment_report._default_report_dir",
                return_value=Path(temp_dir),
            ):
                with TestClient(
                    api_server.app, client=("127.0.0.1", 12345)
                ) as client:
                    response = client.get(
                        f"/api/reports/web-assessments/{artifact['report_id']}.pdf"
                    )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["content-type"], "application/pdf")
            self.assertIn("attachment", response.headers["content-disposition"])
            self.assertEqual(response.content, Path(artifact["path"]).read_bytes())

    def test_download_route_rejects_non_loopback_clients(self) -> None:
        with TestClient(
            api_server.app, client=("192.0.2.20", 12345)
        ) as client:
            response = client.get(
                "/api/reports/web-assessments/0123456789abcdef0123456789abcdef.pdf"
            )

        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
