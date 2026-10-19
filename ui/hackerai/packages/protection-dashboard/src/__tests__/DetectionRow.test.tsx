import { render, screen } from "@testing-library/react";
import { DetectionRow } from "../components/DetectionRow";
import type { DetectionRecord } from "../protection-api";

test("renders exact hash intelligence as advisory evidence", () => {
  const detection: DetectionRecord = {
    detection_id: "det-intel-1",
    action: "allow",
    confidence: "low",
    severity: "high",
    file_type: ".exe",
    size_bytes: 512,
    file_path: "C:/Temp/sample.exe",
    created_at: "2026-10-14T12:00:00",
    triage_enqueued: false,
    threat_intel_evidence: {
      indicator_type: "sha256",
      indicator_value: "a".repeat(64),
      source: "abusech_malwarebazaar",
      verification: "confirmed",
      confidence: 95,
      severity: "high",
      feed_version: "feed-42",
      first_seen: "2026-10-14T10:00:00",
      last_seen: "2026-10-14T11:00:00",
      freshness: "fresh",
      corroborations: 1,
      block_eligible: true,
      decision_reason: "eligible in store; advisory in P2A",
    },
  };

  render(<DetectionRow detection={detection} />);

  expect(screen.getByText(/Advisory exact SHA-256 match/)).toBeInTheDocument();
  expect(screen.getByText("Advisory only")).toBeInTheDocument();
  expect(screen.getByText("a".repeat(64))).toBeInTheDocument();
});

test("keeps retracted and expired matches visible as advisory evidence", () => {
  const detection: DetectionRecord = {
    detection_id: "det-retracted",
    action: "allow",
    confidence: "low",
    severity: "medium",
    file_type: ".exe",
    size_bytes: 1,
    file_path: "C:/Temp/retracted.exe",
    created_at: "2026-10-14T12:00:00",
    triage_enqueued: false,
    threat_intel_evidence: {
      indicator_type: "sha256",
      indicator_value: "b".repeat(64),
      source: "test-source",
      verification: "retracted",
      confidence: 0,
      severity: "medium",
      feed_version: "feed-1",
      first_seen: "2026-01-01T00:00:00",
      last_seen: "2026-01-01T00:00:00",
      freshness: "expired",
      corroborations: 1,
      block_eligible: false,
      decision_reason: "source retracted this indicator",
    },
  };
  render(<DetectionRow detection={detection} />);
  expect(screen.getByText(/retracted · expired/)).toBeInTheDocument();
  expect(screen.getByText("Advisory only")).toBeInTheDocument();
});
