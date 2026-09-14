"use client";

import { ArrowDownToLine, ArrowUpFromLine } from "lucide-react";
import type { ToolWorkspaceContent } from "@/app/contexts/ToolWorkspaceContext";

export function HttpInspectorWorkspace({ content }: { content: ToolWorkspaceContent }) {
  return (
    <div className="h-full overflow-auto p-4 text-xs">
      <section>
        <div className="mb-2 flex items-center gap-2 font-medium"><ArrowUpFromLine className="size-4" aria-hidden="true" /> Request</div>
        <div className="rounded border border-border bg-muted/20 p-3 font-mono break-all">{content.method || "GET"} {content.url || "URL unavailable"}</div>
        {content.requestHeaders ? <pre className="mt-2 overflow-auto rounded border border-border p-3 font-mono">{JSON.stringify(content.requestHeaders, null, 2)}</pre> : null}
      </section>
      <section className="mt-6">
        <div className="mb-2 flex items-center gap-2 font-medium"><ArrowDownToLine className="size-4" aria-hidden="true" /> Response <span className="text-muted-foreground">{content.responseStatus ?? "pending"}</span></div>
        {content.responseBody ? <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap break-words rounded border border-border bg-muted/20 p-3 font-mono">{content.responseBody}</pre> : <p className="text-muted-foreground">Response body unavailable.</p>}
      </section>
    </div>
  );
}
