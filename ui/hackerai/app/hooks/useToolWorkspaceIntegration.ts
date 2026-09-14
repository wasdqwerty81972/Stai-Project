"use client";

import { useCallback, useMemo } from "react";
import { useToolWorkspace } from "@/app/contexts/ToolWorkspaceContext";
import type { ToolWorkspaceContent } from "@/app/contexts/ToolWorkspaceContext";

interface UseToolWorkspaceIntegrationOptions {
  /** The toolCallId for this tool invocation */
  toolCallId: string;
  /** The session ID for this investigation */
  sessionId: string;
  /** The content to display when this tool's workspace is opened */
  content: ToolWorkspaceContent | null;
  /** Type guard to check if current workspace is this tool's type */
  typeGuard: (content: ToolWorkspaceContent) => boolean;
}

interface UseToolWorkspaceIntegrationResult {
  /** Open this tool's workspace */
  handleOpenWorkspace: () => void;
  /** Whether this tool's workspace is currently active */
  isWorkspaceActive: boolean;
  /** Close the workspace */
  handleCloseWorkspace: () => void;
}

/**
 * Hook to integrate a tool with the workspace system.
 * 
 * Usage:
 * ```tsx
 * const { handleOpenWorkspace, isWorkspaceActive } = useToolWorkspaceIntegration({
 *   toolCallId: part.toolCallId,
 *   sessionId,
 *   content: sidebarContent,
 *   typeGuard: (c) => c.type === "terminal",
 * });
 * 
 * // In tool block:
 * <button onClick={handleOpenWorkspace}>View terminal</button>
 * ```
 */
export function useToolWorkspaceIntegration({
  toolCallId,
  sessionId,
  content,
  typeGuard,
}: UseToolWorkspaceIntegrationOptions): UseToolWorkspaceIntegrationResult {
  const {
    workspaceOpen,
    workspaceContent,
    openWorkspace,
    closeWorkspace,
  } = useToolWorkspace();

  const isWorkspaceActive = useMemo(() => {
    return (
      workspaceOpen &&
      workspaceContent !== null &&
      typeGuard(workspaceContent) &&
      workspaceContent.toolCallId === toolCallId
    );
  }, [workspaceOpen, workspaceContent, toolCallId, typeGuard]);

  const handleOpenWorkspace = useCallback(() => {
    if (!content) return;
    openWorkspace({
      ...content,
      toolCallId,
      sessionId,
    });
  }, [content, toolCallId, sessionId, openWorkspace]);

  const handleCloseWorkspace = useCallback(() => {
    closeWorkspace();
  }, [closeWorkspace]);

  return {
    handleOpenWorkspace,
    isWorkspaceActive,
    handleCloseWorkspace,
  };
}
