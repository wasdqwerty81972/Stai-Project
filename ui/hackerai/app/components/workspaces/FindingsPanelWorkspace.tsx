"use client";

import { ShieldAlert } from "lucide-react";
import type { ToolWorkspaceContent } from "@/app/contexts/ToolWorkspaceContext";

const severityClass: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
};

export function FindingsPanelWorkspace({ content }: { content: ToolWorkspaceContent }) {
  const findings = content.findings || [];
  return (
    <div className="h-full overflow-auto p-4">
      <div className="flex items-center gap-2 text-sm font-medium"><ShieldAlert className="size-4" aria-hidden="true" /> Security findings</div>
      <div className="mt-4 grid grid-cols-4 gap-2 text-center text-xs">
        {(["critical", "high", "medium", "low"] as const).map((severity) => <div key={severity} className="rounded border border-border p-2"><div className={severityClass[severity]}>{findings.filter((finding) => finding.severity === severity).length}</div><div className="mt-1 text-muted-foreground">{severity}</div></div>)}
      </div>
      <div className="mt-4 space-y-2">
        {findings.length === 0 ? <p className="text-xs text-muted-foreground">No findings were reported.</p> : findings.map((finding, index) => <article key={`${finding.type}-${index}`} className="rounded border border-border bg-muted/20 p-3 text-xs"><div className={`font-medium ${severityClass[finding.severity] || ""}`}>{finding.severity.toUpperCase()} · {finding.type}</div><p className="mt-1">{finding.message}</p>{finding.location ? <div className="mt-2 font-mono text-muted-foreground">{finding.location}</div> : null}</article>)}
      </div>
    </div>
  );
}
