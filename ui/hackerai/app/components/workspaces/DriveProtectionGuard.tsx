"use client";

/**
 * DriveProtectionGuard — H:\ and F:\ drive protection for SVS-Cyber.
 *
 * F:\ = HackerAI source reference. READ ONLY. Any mutation attempt → blocked.
 * H:\ = Target drive. Verify availability before scanning.
 *
 * This guard is rendered by tool workspace components when a filesystem path
 * is involved. It never fabricates results.
 */

import { AlertTriangle, Lock, HardDrive } from "lucide-react";

interface DriveGuardResult {
  blocked: boolean;
  reason?: "REFERENCE_FILESYSTEM_READ_ONLY" | "TARGET_NOT_MOUNTED" | "PERMISSION_DENIED";
  message?: string;
}

export function checkDriveAccess(
  path: string,
  operation: "read" | "write" | "delete" | "rename",
): DriveGuardResult {
  const normalized = path.toUpperCase().replace(/\//g, "\\");

  // F:\ is the HackerAI reference — always read-only
  if (normalized.startsWith("F:\\") || normalized.startsWith("F:/")) {
    if (operation !== "read") {
      return {
        blocked: true,
        reason: "REFERENCE_FILESYSTEM_READ_ONLY",
        message:
          "F:\\ is the HackerAI source reference and is read-only. " +
          `${operation.charAt(0).toUpperCase() + operation.slice(1)} operations are blocked.`,
      };
    }
  }

  return { blocked: false };
}

// ─── UI Components ────────────────────────────────────────────────────────────

interface DriveBlockedProps {
  path: string;
  reason: DriveGuardResult["reason"];
  message?: string;
}

export function DriveBlockedNotice({ path, reason, message }: DriveBlockedProps) {
  const icon =
    reason === "REFERENCE_FILESYSTEM_READ_ONLY" ? (
      <Lock className="size-4 text-amber-500 shrink-0" />
    ) : reason === "TARGET_NOT_MOUNTED" ? (
      <HardDrive className="size-4 text-muted-foreground shrink-0" />
    ) : (
      <AlertTriangle className="size-4 text-destructive shrink-0" />
    );

  const title =
    reason === "REFERENCE_FILESYSTEM_READ_ONLY"
      ? "Reference Filesystem — Read Only"
      : reason === "TARGET_NOT_MOUNTED"
        ? "Drive Not Mounted"
        : "Permission Denied";

  const description =
    message ??
    (reason === "REFERENCE_FILESYSTEM_READ_ONLY"
      ? `F:\\ is the HackerAI source reference. It is read-only and cannot be modified.`
      : reason === "TARGET_NOT_MOUNTED"
        ? `The drive at ${path} is not accessible. Verify it is mounted and try again.`
        : `Access to ${path} was denied.`);

  return (
    <div className="flex items-start gap-3 rounded-lg border border-border bg-muted/20 p-4 text-sm">
      {icon}
      <div className="min-w-0 flex-1 space-y-1">
        <p className="font-medium">{title}</p>
        <p className="text-xs text-muted-foreground">{description}</p>
        <code className="block text-xs font-mono text-muted-foreground/70 mt-1">
          {path}
        </code>
      </div>
    </div>
  );
}

interface HdriveNoticeProps {
  status: "checking" | "available" | "not_mounted" | "permission_denied";
  path?: string;
}

export function HDriveStatusNotice({ status, path = "H:\\" }: HdriveNoticeProps) {
  if (status === "checking") {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-muted-foreground" />
        Verifying access to {path}…
      </div>
    );
  }

  if (status === "not_mounted") {
    return (
      <DriveBlockedNotice
        path={path}
        reason="TARGET_NOT_MOUNTED"
        message={`TARGET_NOT_MOUNTED: ${path} is not accessible. Verify the drive is connected and mounted.`}
      />
    );
  }

  if (status === "permission_denied") {
    return (
      <DriveBlockedNotice
        path={path}
        reason="PERMISSION_DENIED"
        message={`PERMISSION_DENIED: The execution agent does not have read access to ${path}.`}
      />
    );
  }

  return null;
}
