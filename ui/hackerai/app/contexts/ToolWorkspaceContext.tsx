"use client";

import React, { createContext, useContext, useState, useCallback, ReactNode } from "react";

/**
 * Represents a tool workspace that can be displayed in the right-side panel.
 * Workspaces are tied to a specific tool execution within an investigation.
 */
export interface ToolWorkspaceContent {
  type: "browser" | "terminal" | "files" | "http" | "findings" | null;
  title: string;
  toolCallId: string;
  sessionId: string;
  agentRunId?: string;
  toolExecutionId?: string;
  status: "running" | "completed" | "failed" | "idle";
  
  // Type-specific data
  command?: string;           // For terminal
  output?: string;            // For terminal
  url?: string;              // For browser
  method?: string;           // For HTTP
  requestHeaders?: Record<string, string>;  // For HTTP
  responseStatus?: number;   // For HTTP
  responseBody?: string;     // For HTTP
  filePath?: string;         // For files
  findings?: Array<{         // For findings
    type: string;
    severity: "critical" | "high" | "medium" | "low";
    message: string;
    location?: string;
  }>;
  
  // Additional metadata
  metadata?: Record<string, any>;
}

interface ToolWorkspaceContextType {
  // Current workspace state
  workspaceOpen: boolean;
  workspaceContent: ToolWorkspaceContent | null;
  workspaceHistory: ToolWorkspaceContent[];
  
  // Actions
  openWorkspace: (content: ToolWorkspaceContent) => void;
  closeWorkspace: () => void;
  updateWorkspaceContent: (content: Partial<ToolWorkspaceContent>) => void;
  selectWorkspace: (toolCallId: string) => void;
}

const ToolWorkspaceContext = createContext<ToolWorkspaceContextType | undefined>(undefined);

/**
 * Provider for tool workspace state.
 * Manages the right-side panel that shows tool execution results.
 */
export function ToolWorkspaceProvider({ children }: { children: ReactNode }) {
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const [workspaceContent, setWorkspaceContent] = useState<ToolWorkspaceContent | null>(null);
  const [workspaceHistory, setWorkspaceHistory] = useState<ToolWorkspaceContent[]>([]);

  const openWorkspace = useCallback((content: ToolWorkspaceContent) => {
    setWorkspaceContent(content);
    setWorkspaceHistory((current) => {
      const withoutCurrent = current.filter((item) => item.toolCallId !== content.toolCallId);
      return [...withoutCurrent, content];
    });
    setWorkspaceOpen(true);
  }, []);

  const closeWorkspace = useCallback(() => {
    setWorkspaceOpen(false);
    // Keep content in memory for a moment in case user reopens
    setTimeout(() => {
      setWorkspaceContent(null);
    }, 300);
  }, []);

  const updateWorkspaceContent = useCallback((updates: Partial<ToolWorkspaceContent>) => {
    setWorkspaceContent((prev) =>
      prev ? { ...prev, ...updates } : null
    );
    setWorkspaceHistory((current) => current.map((item) =>
      item.toolCallId === updates.toolCallId || (item.toolCallId && updates.toolCallId === undefined && item.toolCallId === workspaceContent?.toolCallId)
        ? { ...item, ...updates }
        : item,
    ));
  }, [workspaceContent?.toolCallId]);

  const selectWorkspace = useCallback((toolCallId: string) => {
    setWorkspaceHistory((current) => {
      const selected = current.find((item) => item.toolCallId === toolCallId);
      if (selected) setWorkspaceContent(selected);
      return current;
    });
    setWorkspaceOpen(true);
  }, []);

  const value: ToolWorkspaceContextType = {
    workspaceOpen,
    workspaceContent,
    workspaceHistory,
    openWorkspace,
    closeWorkspace,
    updateWorkspaceContent,
    selectWorkspace,
  };

  return (
    <ToolWorkspaceContext.Provider value={value}>
      {children}
    </ToolWorkspaceContext.Provider>
  );
}

/**
 * Hook to access tool workspace state and actions.
 * Use this in tool handlers and components that need to open/close the workspace.
 */
export function useToolWorkspace(): ToolWorkspaceContextType {
  const context = useContext(ToolWorkspaceContext);
  if (context === undefined) {
    throw new Error("useToolWorkspace must be used within ToolWorkspaceProvider");
  }
  return context;
}

/**
 * Hook to check if the workspace is currently showing a specific tool.
 */
export function useIsToolActive(toolCallId: string): boolean {
  const { workspaceOpen, workspaceContent } = useToolWorkspace();
  return (
    workspaceOpen &&
    workspaceContent !== null &&
    workspaceContent.toolCallId === toolCallId
  );
}
