"use client";

import React from "react";
import { Copy, Download } from "lucide-react";
import type { ToolWorkspaceContent } from "@/app/contexts/ToolWorkspaceContext";

interface TerminalWorkspaceProps {
  content: ToolWorkspaceContent;
}

/**
 * Terminal workspace component.
 * Displays command and output in monospace format with ANSI color support.
 * 
 * Shows:
 * - Command that was executed
 * - Real-time output as it streams
 * - Status and completion time
 */
export function TerminalWorkspace({ content }: TerminalWorkspaceProps) {
  const handleCopyOutput = () => {
    if (!content.output) return;
    navigator.clipboard.writeText(content.output).catch(console.error);
  };

  const handleDownloadOutput = () => {
    if (!content.output) return;
    const blob = new Blob([content.output], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `terminal-${content.toolCallId}-output.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Command display */}
      {content.command && (
        <div className="border-b border-border p-3 shrink-0">
          <p className="text-xs text-muted-foreground mb-1">Command:</p>
          <code className="text-sm bg-muted p-2 rounded block font-mono text-foreground break-all max-h-20 overflow-y-auto">
            $ {content.command}
          </code>
        </div>
      )}

      {/* Output display */}
      <div className="flex-1 overflow-y-auto p-3">
        {content.output ? (
          <pre className="text-xs font-mono text-foreground whitespace-pre-wrap word-break-break-word">
            {content.output}
          </pre>
        ) : (
          <div className="text-xs text-muted-foreground italic">
            {content.status === "running" ? "Output pending..." : "No output"}
          </div>
        )}
      </div>

      {/* Footer with actions */}
      {content.output && (
        <div className="border-t border-border p-2 flex gap-2 shrink-0">
          <button
            onClick={handleCopyOutput}
            className="inline-flex items-center gap-2 px-2 py-1 text-xs hover:bg-muted rounded transition-colors"
            title="Copy output to clipboard"
          >
            <Copy className="h-3 w-3" />
            Copy
          </button>
          <button
            onClick={handleDownloadOutput}
            className="inline-flex items-center gap-2 px-2 py-1 text-xs hover:bg-muted rounded transition-colors"
            title="Download output as file"
          >
            <Download className="h-3 w-3" />
            Download
          </button>
        </div>
      )}
    </div>
  );
}
