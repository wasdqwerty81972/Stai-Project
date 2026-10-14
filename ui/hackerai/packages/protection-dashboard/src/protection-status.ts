/**
 * Pure protection-status interpretation.
 *
 * This module intentionally has no runtime imports: components and tests can
 * use it while the Tauri IPC layer in `protection-api` is mocked out.
 */
import type { DeviceActivity, ProtectionStatus } from "./protection-api";

/**
 * Rule package versions that only carry test content. The installer copies
 * the EICAR demonstration package when no real package is present, so an
 * "active" service can still have effectively no malware coverage.
 */
const DEMO_RULE_VERSIONS = new Set(["svs-eicar-demo-1"]);

export function isDemoRuleVersion(version: string | null | undefined): boolean {
  return typeof version === "string" && DEMO_RULE_VERSIONS.has(version);
}

/** Protection tiers the dashboard is allowed to claim, strongest first. */
export type ProtectionTier = "kernel_verified" | "user_mode_only" | "unavailable";

export interface ProtectionVerdict {
  tier: ProtectionTier;
  /** True only when the kernel filter is connected AND rule coverage is real. */
  verifiedProtection: boolean;
  title: string;
  detail: string;
  /** Each limit is a concrete, service-reported reason - never a guess. */
  limits: string[];
}

function driverReason(status: ProtectionStatus): string {
  const driver = status.driver_state ?? "not reported";
  if (driver === "stopped") {
    return "The Windows file filter driver is not connected, so file operations are not inspected or blocked in real time.";
  }
  if (driver === "error") {
    return "The Windows file filter driver reported an error, so real-time file blocking is not in effect.";
  }
  return `The service did not confirm a connected file filter driver (driver state: ${driver}).`;
}

/**
 * Collapse the service status into the single claim the UI may display.
 *
 * The result is deliberately pessimistic: anything the service did not
 * positively confirm downgrades the tier, and limited rule coverage can
 * never produce a verified-protection result.
 */
export function summarizeProtection(
  status: ProtectionStatus | null,
  statusError: string | null,
): ProtectionVerdict {
  if (statusError || !status) {
    return {
      tier: "unavailable",
      verifiedProtection: false,
      title: "Protection status unknown",
      detail:
        statusError ||
        "The local protection service did not report a status, so this device's protection cannot be confirmed.",
      limits: [],
    };
  }

  const limits: string[] = [];
  if (status.rules_trusted === false) {
    limits.push(
      "The local service could not verify a signed rule package, so no rule-based detection is in effect.",
    );
  } else if (isDemoRuleVersion(status.rules_version)) {
    limits.push(
      "The active rule package is the EICAR demonstration package. It detects the EICAR test file only and provides no real malware coverage.",
    );
  } else if (!status.rules_version || status.rules_version === "unknown") {
    limits.push("The service did not report a verified rule package version.");
  }
  if (status.network_telemetry && status.network_telemetry.state !== "running") {
    limits.push(
      `Network telemetry is not active (reported state: ${status.network_telemetry.state.replaceAll("_", " ")}). Connections are listed from user-mode polling only and are not filtered.`,
    );
  }

  if (status.state === "unavailable") {
    return {
      tier: "unavailable",
      verifiedProtection: false,
      title: "Protection is not active",
      detail:
        status.last_error ||
        limits[0] ||
        "The local protection service did not confirm an active state.",
      limits,
    };
  }

  const kernelConnected = status.driver_state === "running";
  const serviceRunning = status.service_state === "running";

  if (status.state === "active" && kernelConnected && serviceRunning) {
    if (limits.length > 0) {
      return {
        tier: "kernel_verified",
        verifiedProtection: false,
        title: "Protection is active with limited coverage",
        detail:
          "The service and the Windows file filter driver are connected, but the coverage below is incomplete.",
        limits,
      };
    }
    return {
      tier: "kernel_verified",
      verifiedProtection: true,
      title: "Protection is active and verified",
      detail:
        "The local service confirmed a running protection service, a connected Windows file filter driver, and a verified rule package.",
      limits,
    };
  }

  if (serviceRunning) {
    if (kernelConnected) {
      // Both components are connected, yet the service still withheld
      // "active". Report its reason instead of inventing a tier.
      return {
        tier: "user_mode_only",
        verifiedProtection: false,
        title: "Protection needs attention",
        detail:
          status.last_error ||
          limits[0] ||
          "The local service reported a degraded state without naming a cause.",
        limits,
      };
    }
    const reason = driverReason(status);
    return {
      tier: "user_mode_only",
      verifiedProtection: false,
      title: "Kernel protection unavailable",
      detail: status.last_error || reason,
      limits: [reason, ...limits],
    };
  }

  return {
    tier: "unavailable",
    verifiedProtection: false,
    title: "Protection is not active",
    detail:
      status.last_error ||
      `The local protection service is not running (service state: ${status.service_state ?? "not reported"}).`,
    limits,
  };
}

export interface RuleMatchingSummary {
  /** Headline label; never claims a usable database unless matching works. */
  label: string;
  /** True only when this collector can actually match rules against files. */
  matching: boolean;
  demo: boolean;
  detail: string;
}

/**
 * Describe the collector's rule database honestly.
 *
 * `available` only means a package was found. Process-level matching also
 * requires `analysis_available`, because the service's rule files are
 * ACL-protected and often unreadable by this user-mode collector.
 */
export function describeRuleMatching(
  database: DeviceActivity["database"] | null | undefined,
): RuleMatchingSummary {
  if (!database || !database.available) {
    return {
      label: "Rule database unavailable",
      matching: false,
      demo: false,
      detail: "No authenticated rule database is available, so no process can be matched against rules.",
    };
  }
  const demo = Boolean(database.demo) || isDemoRuleVersion(database.version);
  if (database.analysis_available === false) {
    return {
      label: "Rule matching unavailable",
      matching: false,
      demo,
      detail: database.active_in_protection_service
        ? "The protection service reports this package as active, but this collector cannot read its rule contents, so process-level rule matching is not running."
        : "A rule package was found but its contents cannot be verified here, so process-level rule matching is not running.",
    };
  }
  if (demo) {
    return {
      label: "Demo rule database",
      matching: true,
      demo: true,
      detail: "Demonstration rules detect the EICAR test file only. They provide no real malware coverage.",
    };
  }
  return {
    label: "Signed rule database",
    matching: true,
    demo: false,
    detail: "Authenticated rules are loaded. No match is not proof that a file is safe.",
  };
}
