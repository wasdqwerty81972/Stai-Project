"""Evidence-bounded PDF reports for URL-scoped web assessments."""

from __future__ import annotations

import json
import re
import ast
import textwrap
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

try:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
except ImportError as exc:  # pragma: no cover - depends on optional runtime setup
    FPDF = None  # type: ignore[assignment,misc]
    XPos = YPos = None  # type: ignore[assignment,misc]
    _FPDF_IMPORT_ERROR: Optional[ImportError] = exc
else:
    _FPDF_IMPORT_ERROR = None


_REPORT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_STEPS = 50
_MAX_EVIDENCE_CHARS = 12000


def _default_report_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "output" / "pdf"


def _pdf_text(value: Any, limit: int = _MAX_EVIDENCE_CHARS) -> str:
    """Convert tool data into bounded, printable core-font text."""
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    elif value is None:
        text = ""
    else:
        text = str(value)
    truncated = len(text) > limit
    text = text[:limit]
    # FPDF's built-in Helvetica font uses Latin-1. Preserve readable accents
    # where possible and replace unsupported glyphs rather than failing a run.
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("latin-1", errors="replace").decode("latin-1")
    if truncated:
        text += "\n[Evidence excerpt truncated at the report limit.]"
    return text


def _step_status(step: Mapping[str, Any]) -> str:
    success = step.get("success")
    _payload, plugin_success = _parse_tool_result(step.get("output"))
    if success is False or plugin_success is False:
        return "FAILED"
    if success is True or plugin_success is True:
        return "COMPLETED"
    status = step.get("status")
    if isinstance(status, str) and status.strip():
        return _pdf_text(status.strip().upper(), limit=40)
    return "UNKNOWN"


def _parse_mapping(value: Any) -> Optional[dict[str, Any]]:
    if isinstance(value, Mapping):
        return dict(value)
    if not isinstance(value, str):
        return None
    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(value)
        except (ValueError, SyntaxError, TypeError):
            continue
        if isinstance(parsed, Mapping):
            return dict(parsed)
    return None


def _parse_tool_result(output: Any) -> tuple[dict[str, Any], Optional[bool]]:
    """Unwrap recorded plugin envelopes without interpreting arbitrary text."""
    parsed = _parse_mapping(output)
    if parsed is None:
        return {}, None
    plugin_success: Optional[bool] = None
    for _ in range(4):
        if isinstance(parsed.get("success"), bool):
            plugin_success = parsed["success"]
        nested = _parse_mapping(parsed.get("output"))
        if nested is None:
            break
        parsed = nested
    return parsed, plugin_success


def _tool_interpretations(steps: list[Mapping[str, Any]]) -> list[str]:
    interpretations: list[str] = []
    for step in steps:
        tool = str(step.get("tool", "")).strip().lower()
        payload, plugin_success = _parse_tool_result(step.get("output"))
        if step.get("success") is False or plugin_success is False:
            continue
        status = str(step.get("status", "")).strip().lower()
        has_success = (
            step.get("success") is True
            or plugin_success is True
            or status in {"success", "successful", "completed", "complete"}
        )
        if not has_success:
            continue

        if tool in {"web_security_headers", "http_headers"}:
            if payload.get("tls_verification") == "verified":
                interpretations.append(
                    "Transport observation: TLS certificate validation succeeded for the tested HTTPS response."
                )
            missing = payload.get("missing_security_headers")
            if not isinstance(missing, list):
                header_map = payload.get("security_headers")
                missing = (
                    [name for name, value in header_map.items()
                     if isinstance(value, str) and value.strip().upper() == "MISSING"]
                    if isinstance(header_map, Mapping)
                    else []
                )
            missing_names = [str(name) for name in missing if isinstance(name, str) and name.strip()]
            if missing_names:
                interpretations.append(
                    "Security-header configuration observation: the response did not include "
                    + ", ".join(missing_names)
                    + ". Missing headers can reduce browser-side hardening in relevant contexts; "
                    "impact depends on application behavior and other controls. This observation "
                    "alone does not establish a vulnerability."
                )
            elif payload.get("security_headers") or "missing_security_headers" in payload:
                interpretations.append(
                    "Security-header configuration observation: the recorded result did not list "
                    "any missing headers. This is limited to the tested response."
                )

        elif tool == "xss_scanner":
            reflected = payload.get("reflected")
            if reflected is True:
                interpretations.append(
                    "XSS probe: the harmless marker appeared in the tested response. This is a "
                    "candidate reflection observation only; the probe did not test browser "
                    "execution or context-specific escaping."
                )
            elif reflected is False:
                interpretations.append(
                    "XSS probe: the harmless marker was not observed in the tested response; "
                    "this does not rule out other XSS paths."
                )

        elif tool == "sqli_scanner":
            possible = payload.get("possible_sqli")
            delta = payload.get("response_length_delta")
            if possible is True:
                detail = (
                    f" (recorded response-length delta: {delta})"
                    if isinstance(delta, (int, float)) and not isinstance(delta, bool)
                    else ""
                )
                interpretations.append(
                    "SQL injection probe: a possible response-length signal was recorded"
                    + detail
                    + ". Response-size differences can have benign causes; this signal needs "
                    "manual validation and does not establish SQL injection."
                )
            elif possible is False:
                interpretations.append(
                    "SQL injection probe: no response-length signal was flagged by this limited check."
                )

        elif tool in {"web_tech_fingerprint", "tech_fingerprint"}:
            technologies = payload.get("technologies")
            names = []
            if isinstance(technologies, list):
                for technology in technologies:
                    if isinstance(technology, Mapping) and isinstance(technology.get("name"), str):
                        name = technology["name"].strip()
                        if name:
                            names.append(name)
                    elif isinstance(technology, str) and technology.strip():
                        names.append(technology.strip())
            if names:
                interpretations.append(
                    "Technology fingerprint inventory: "
                    + ", ".join(dict.fromkeys(names))
                    + ". This is technology inventory only; product or banner identification "
                    "does not establish a vulnerability."
                )
            elif payload.get("detected") is False or "technologies" in payload:
                interpretations.append(
                    "Technology fingerprint inventory: no technology was identified in the "
                    "recorded result; this does not establish that none are present."
                )
    return interpretations


def _format_evidence(value: Any) -> str:
    """Render structured tool output as readable, wrapped plain text."""
    parsed = _parse_mapping(value)
    if parsed is not None:
        value = parsed

    lines: list[str] = []

    def add_scalar(label: str, scalar: Any, indent: int) -> None:
        prefix = " " * indent
        if scalar is None:
            return
        if isinstance(scalar, str):
            content = scalar.replace("\r\n", "\n").replace("\r", "\n").strip()
            if not content:
                return
            normalized_lines: list[str] = []
            for raw_line in content.splitlines():
                clean_line = raw_line.strip()
                if clean_line:
                    normalized_lines.append(clean_line)
                elif normalized_lines and normalized_lines[-1]:
                    normalized_lines.append("")
            content = "\n".join(normalized_lines).strip()
            if "\n" in content or len(content) > 100:
                lines.append(f"{prefix}{label}:")
                for raw_line in content.splitlines():
                    if not raw_line:
                        if lines and lines[-1] != "":
                            lines.append("")
                        continue
                    wrapped = textwrap.wrap(
                        raw_line,
                        width=max(30, 96 - indent - 2),
                        break_long_words=True,
                        break_on_hyphens=False,
                    ) or [""]
                    lines.extend(prefix + "  " + chunk for chunk in wrapped)
                while lines and not lines[-1]:
                    lines.pop()
            else:
                lines.append(
                    f"{prefix}- {content}" if label == "-" else f"{prefix}{label}: {content}"
                )
        else:
            lines.append(f"{prefix}{label}: {scalar}")

    def walk(item: Any, indent: int = 0, label: str = "") -> None:
        if isinstance(item, Mapping):
            if label:
                lines.append(" " * indent + label + ":")
                indent += 2
            for key, nested in item.items():
                key_text = str(key)
                if isinstance(nested, Mapping):
                    walk(nested, indent, key_text)
                elif isinstance(nested, list):
                    lines.append(" " * indent + key_text + ":")
                    walk(nested, indent + 2)
                else:
                    add_scalar(key_text, nested, indent)
        elif isinstance(item, list):
            for nested in item:
                if isinstance(nested, (Mapping, list)):
                    lines.append(" " * indent + "-")
                    walk(nested, indent + 2)
                else:
                    add_scalar("-", nested, indent)
        else:
            add_scalar(label or "value", item, indent)

    walk(value)
    if lines:
        return "\n".join(lines)
    return "" if isinstance(value, (Mapping, list)) or value is None else _pdf_text(value)


def _executive_summary(steps: list[Mapping[str, Any]]) -> str:
    statuses = [_step_status(step) for step in steps]
    completed = statuses.count("COMPLETED")
    failed = statuses.count("FAILED")
    unknown = statuses.count("UNKNOWN")
    lines = [
        f"Coverage: {len(steps)} recorded tool steps; {completed} completed, {failed} failed, {unknown} unknown.",
        "Outcome: No confirmed vulnerabilities were established by the limited checks performed. "
        "This result does not determine whether other paths are vulnerable.",
        "Scope: Checks used the supplied URL only and did not crawl linked pages or test authenticated routes.",
    ]
    lines.extend(_tool_interpretations(steps))
    lines.append("No CSRF-specific check was performed.")
    return "\n".join(lines)


class _AssessmentPDF(FPDF):
    def __init__(self, report_id: str, generated_at: str) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.report_id = report_id
        self.generated_at = generated_at
        self.set_margins(18, 18, 18)
        self.set_auto_page_break(auto=True, margin=18)

    def multi_cell(self, *args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("new_x", XPos.LMARGIN)
        kwargs.setdefault("new_y", YPos.NEXT)
        kwargs.setdefault("align", "L")
        return super().multi_cell(*args, **kwargs)

    def header(self) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(73, 84, 96)
        self.cell(
            0,
            6,
            "SVS-CYBER | URL-SCOPED WEB ASSESSMENT",
            border=0,
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        self.set_draw_color(190, 199, 207)
        self.line(18, 26, 192, 26)
        self.ln(5)

    def footer(self) -> None:
        self.set_y(-14)
        self.set_font("Helvetica", size=8)
        self.set_text_color(100, 110, 120)
        self.cell(0, 8, f"Report {self.report_id} | Page {self.page_no()}", align="C")


def write_web_assessment_pdf(
    target_url: str,
    tool_steps: Iterable[Mapping[str, Any]],
    *,
    output_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """Write an evidence-bounded assessment PDF and return its safe identifier.

    Tool outputs are included as recorded evidence. This writer does not infer,
    confirm, or add vulnerability findings from those outputs.
    """
    if FPDF is None:
        raise RuntimeError(
            "PDF reporting requires fpdf2; install it with `pip install fpdf2`."
        ) from _FPDF_IMPORT_ERROR
    if not isinstance(target_url, str) or not target_url:
        raise ValueError("target_url must be a non-empty string")

    report_id = uuid.uuid4().hex
    base_dir = Path(output_dir) if output_dir is not None else _default_report_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    output_path = base_dir / f"web-assessment-{report_id}.pdf"

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    pdf = _AssessmentPDF(report_id, generated_at)
    pdf.add_page()
    pdf.set_text_color(25, 35, 45)
    pdf.set_font("Helvetica", "B", 19)
    pdf.multi_cell(0, 10, "URL-Scoped Web Assessment Report")
    pdf.ln(2)

    pdf.set_font("Helvetica", size=10)
    pdf.multi_cell(0, 6, f"Report ID: {report_id}")
    pdf.multi_cell(0, 6, f"Generated: {generated_at}")
    pdf.multi_cell(0, 6, f"Exact target: {_pdf_text(target_url, limit=4096)}")
    pdf.ln(4)

    steps: list[Mapping[str, Any]] = []
    for step in tool_steps:
        if len(steps) >= _MAX_STEPS:
            break
        if isinstance(step, Mapping):
            steps.append(step)

    pdf.set_font("Helvetica", "B", 13)
    pdf.multi_cell(0, 8, "Executive summary")
    pdf.set_font("Helvetica", size=9)
    for summary_line in _executive_summary(steps).splitlines():
        pdf.multi_cell(0, 5, _pdf_text(summary_line, limit=1800))
        pdf.ln(1)
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 13)
    pdf.multi_cell(0, 8, "Recorded tool outcomes")
    pdf.set_font("Helvetica", size=9)
    pdf.multi_cell(
        0,
        5,
        "Statuses and evidence below come from the recorded tool steps. "
        "UNKNOWN means no success or failure status was recorded.",
    )
    pdf.ln(2)

    if not steps:
        pdf.set_font("Helvetica", "I", 10)
        pdf.multi_cell(0, 6, "No tool steps were recorded for this assessment.")

    for index, step in enumerate(steps, 1):
        tool_name = _pdf_text(step.get("tool", "Unknown tool"), limit=120) or "Unknown tool"
        status = _step_status(step)
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 11)
        pdf.multi_cell(0, 7, f"{index}. {tool_name} - {status}")

        arguments = step.get("arguments")
        if arguments:
            pdf.set_font("Helvetica", "B", 9)
            pdf.multi_cell(0, 5, "Recorded arguments:")
            pdf.set_font("Courier", size=8)
            pdf.multi_cell(0, 4, _pdf_text(arguments, limit=2000))

        error = step.get("error")
        output = step.get("output")
        if error:
            pdf.set_font("Helvetica", "B", 9)
            pdf.multi_cell(0, 5, "Recorded error:")
            pdf.set_font("Courier", size=8)
            pdf.multi_cell(0, 4, _pdf_text(error, limit=3000))
        if output:
            pdf.set_font("Helvetica", "B", 9)
            pdf.multi_cell(0, 5, "Recorded tool output (evidence):")
            pdf.set_font("Courier", size=8)
            pdf.multi_cell(0, 4, _pdf_text(_format_evidence(output)))
        if not error and not output:
            pdf.set_font("Helvetica", "I", 9)
            pdf.multi_cell(0, 5, "No output or error text was recorded.")

    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.multi_cell(0, 7, "Evidence interpretation")
    interpretations = _tool_interpretations(steps)
    pdf.set_font("Helvetica", size=9)
    if interpretations:
        for interpretation in interpretations:
            pdf.multi_cell(0, 5, "- " + _pdf_text(interpretation, limit=1800))
            pdf.ln(1)
    else:
        pdf.multi_cell(
            0,
            5,
            "No structured interpretation was added because the recorded results did not "
            "contain supported evidence fields.",
        )

    if len(steps) >= _MAX_STEPS:
        pdf.ln(3)
        pdf.set_font("Helvetica", "I", 9)
        pdf.multi_cell(0, 5, f"Only the first {_MAX_STEPS} recorded steps are included.")

    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.multi_cell(0, 7, "Recommended follow-up")
    pdf.set_font("Helvetica", size=9)
    recommendations = (
        "Review the missing response headers against the application's behavior and deployment; "
        "test CSP and frame protections before enforcing them.",
        "For broader coverage, assess discovered paths and authenticated workflows with authorized "
        "test credentials. This run did not crawl linked pages or log in.",
        "Validate input handling on application-specific parameters and forms. Test CSRF separately "
        "in a controlled session; this run made no state-changing requests.",
    )
    for recommendation in recommendations:
        pdf.multi_cell(0, 5, "- " + _pdf_text(recommendation, limit=1200))
        pdf.ln(1)

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.multi_cell(0, 7, "Scope and limitations")
    pdf.set_font("Helvetica", size=9)
    pdf.multi_cell(
        0,
        5,
        "No findings are inferred or added by this report writer. No CSRF-specific check "
        "was performed. Tool output is "
        "recorded evidence and may require analyst validation. A missing, failed, "
        "or inconclusive check does not establish that a vulnerability exists or "
        "that the target is free of vulnerabilities.",
    )

    pdf.output(str(output_path))
    return {"success": True, "report_id": report_id, "path": str(output_path)}


def get_web_assessment_report_path(report_id: str) -> Path:
    """Resolve an existing generated report without accepting path fragments."""
    if not isinstance(report_id, str) or not _REPORT_ID_RE.fullmatch(report_id):
        raise ValueError("Invalid web assessment report identifier")
    base_dir = _default_report_dir().resolve()
    report_path = (base_dir / f"web-assessment-{report_id}.pdf").resolve()
    if report_path.parent != base_dir:
        raise ValueError("Report path escapes the web assessment report directory")
    if not report_path.is_file():
        raise FileNotFoundError("Web assessment report was not found")
    return report_path
