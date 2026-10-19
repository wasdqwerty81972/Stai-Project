"use client";

import { ExternalLink, Globe, Monitor } from "lucide-react";
import type { ToolWorkspaceContent } from "@/app/contexts/ToolWorkspaceContext";

export function BrowserWorkspace({ content }: { content: ToolWorkspaceContent }) {
  const screenshot = typeof content.metadata?.screenshot === "string"
    ? content.metadata.screenshot
    : null;
  const runtimeAvailable = content.metadata?.runtimeAvailable === true;

  return (
    <div className="flex h-full flex-col bg-background">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <Globe className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div className="min-w-0 flex-1 truncate rounded border border-border bg-muted/30 px-2 py-1 font-mono text-xs text-muted-foreground">
          {content.url || "No URL reported"}
        </div>
        {content.url ? (
          <a href={content.url} target="_blank" rel="noreferrer" aria-label="Open URL in new tab" className="text-muted-foreground hover:text-foreground">
            <ExternalLink className="size-4" aria-hidden="true" />
          </a>
        ) : null}
      </div>
      <div className="flex min-h-0 flex-1 items-center justify-center p-4">
        {screenshot ? (
          <img src={screenshot} alt={content.title || "Browser screenshot"} className="max-h-full max-w-full object-contain" />
        ) : (
          <div className="max-w-sm text-center">
            <Monitor className="mx-auto mb-3 size-8 text-muted-foreground" aria-hidden="true" />
            <p className="text-sm font-medium">Browser workspace</p>
            <p className="mt-2 text-xs text-muted-foreground">
              {runtimeAvailable ? "The browser runtime has not provided a screenshot yet." : "Browser runtime unavailable. Showing the recorded navigation state only."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
