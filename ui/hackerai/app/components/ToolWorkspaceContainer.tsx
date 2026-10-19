"use client";

import React, { useMemo } from "react";
import { X, Terminal, Globe, FileText, Code2, AlertCircle } from "lucide-react";
import { useToolWorkspace } from "@/app/contexts/ToolWorkspaceContext";
import type { ToolWorkspaceContent } from "@/app/contexts/ToolWorkspaceContext";
import { TerminalWorkspace } from "./workspaces/TerminalWorkspace";
import { BrowserWorkspace } from "./workspaces/BrowserWorkspace";
import { FileExplorerWorkspace } from "./workspaces/FileExplorerWorkspace";
import { HttpInspectorWorkspace } from "./workspaces/HttpInspectorWorkspace";
import { FindingsPanelWorkspace } from "./workspaces/FindingsPanelWorkspace";

interface ToolWorkspaceContainerProps {
  /** Whether the container should be visible */
  isVisible?: boolean;
}

/**
 * Right-side tool workspace container.
 * 
 * Displays rich UI for tool execution based on workspace type.
 * Slides in from the right side when a tool is active.
 * 
 * CRITICAL: Opening this workspace does NOT create a new chat.
 * It displays rich UI for the current tool within the same investigation.
 */
export function ToolWorkspaceContainer({ isVisible = true }: ToolWorkspaceContainerProps) {
  const { workspaceOpen, workspaceContent, closeWorkspace } = useToolWorkspace();

  const shouldRender = isVisible && workspaceOpen && workspaceContent !== null;

  const workspaceIcon = useMemo(() => {
    switch (workspaceContent?.type) {
      case "terminal":
        return <Terminal className="h-4 w-4" />;
      case "browser":
        return <Globe className="h-4 w-4" />;
      case "files":
        return <FileText className="h-4 w-4" />;
      case "http":
        return <Code2 className="h-4 w-4" />;
      case "findings":
        return <AlertCircle className="h-4 w-4" />;
      default:
        return null;
    }
  }, [workspaceContent?.type]);

  const renderWorkspaceContent = () => {
    if (!workspaceContent) return null;

    switch (workspaceContent.type) {
      case "terminal":
        return <TerminalWorkspace content={workspaceContent} />;
      case "browser":
        return <BrowserWorkspace content={workspaceContent} />;
      case "files":
        return <FileExplorerWorkspace content={workspaceContent} />;
      case "http":
        return <HttpInspectorWorkspace content={workspaceContent} />;
      case "findings":
        return <FindingsPanelWorkspace content={workspaceContent} />;
      default:
        return <div className="p-4 text-muted-foreground">Unknown workspace type</div>;
    }
  };

  return (
    <>
      {/* Overlay backdrop on mobile */}
      {shouldRender && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={closeWorkspace}
          aria-hidden="true"
        />
      )}

      {/* Workspace panel */}
      <div
        className={`
          fixed right-0 top-0 bottom-0 z-50
          w-full md:w-2/5 lg:w-1/3
          bg-background border-l border-border
          flex flex-col
          transition-transform duration-300 ease-out
          ${shouldRender ? "translate-x-0 pointer-events-auto" : "translate-x-full pointer-events-none"}
        `}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
          <div className="flex items-center gap-2">
            {workspaceIcon}
            <div className="flex-1 min-w-0">
              <h3 className="font-semibold text-sm truncate">
                {workspaceContent?.title || "Tool Output"}
              </h3>
              {workspaceContent?.status && (
                <p className="text-xs text-muted-foreground">
                  {workspaceContent.status === "running" && "Running..."}
                  {workspaceContent.status === "completed" && "Completed"}
                  {workspaceContent.status === "failed" && "Failed"}
                  {workspaceContent.status === "idle" && "Ready"}
                </p>
              )}
            </div>
          </div>

          {/* Close button */}
          <button
            onClick={closeWorkspace}
            className="inline-flex items-center justify-center h-8 w-8 rounded-lg hover:bg-muted transition-colors"
            aria-label="Close workspace"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content area */}
        <div className="flex-1 overflow-hidden">
          {renderWorkspaceContent()}
        </div>
      </div>
    </>
  );
}

export default ToolWorkspaceContainer;
