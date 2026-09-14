"use client";

/**
 * StaiGlobalState — Lightweight SVS-Cyber replacement for HackerAI's GlobalState.
 *
 * HackerAI's GlobalState (1377 lines) depends on Convex, WorkOS, PostHog, and
 * many SaaS-specific subsystems. SVS-Cyber does not use any of these. This
 * module provides the exact same context interface so HackerAI UI components
 * (ChatInputTextarea, SubmitStopButton, ChatInputToolbar, ModelSelector, etc.)
 * can be used unchanged — only the backing data is different.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { UploadedFileState } from "@/types/file";
import {
  ComposerStateProvider,
  useComposerActions,
} from "@/app/contexts/ComposerState";

// ─── Types (subset of HackerAI GlobalState) ──────────────────────────────────

export type ChatMode = "agent" | "ask";
export type SelectedModel =
  | "auto"
  | "gemini"
  | "omniroute"
  | "svs-cyber-ai"
  | "3-brain-stack";
export type SandboxPreference = "local" | "e2b" | "desktop" | null;
export type SubscriptionTier = "free" | "pro" | "team";
export type AgentPermissionMode = "normal" | "cautious" | "yolo";
export type QueueBehavior = "queue" | "replace";
export type SidebarContent = { type: string; data?: unknown };

export interface QueuedMessage {
  id: string;
  content: string;
  createdAt: number;
}

export interface Todo {
  id: string;
  content: string;
  status: "pending" | "in_progress" | "completed";
}

// ─── SVS-Cyber model definitions ─────────────────────────────────────────────

export const SVS_MODELS: Array<{
  id: SelectedModel;
  label: string;
  description: string;
  available: boolean;
  badge?: string;
}> = [
  {
    id: "auto",
    label: "Automatic",
    description: "Use SVS-Cyber's configured local provider routing",
    available: true,
  },
  {
    id: "gemini",
    label: "Gemini",
    description: "Google Gemini — fast general-purpose",
    available: true,
  },
  {
    id: "omniroute",
    label: "OmniRoute",
    description: "SVS-Cyber OmniRoute — balanced routing",
    available: true,
  },
  {
    id: "svs-cyber-ai",
    label: "SVS-Cyber AI",
    description: "Specialized defensive security model",
    available: true,
  },
  {
    id: "3-brain-stack",
    label: "3-Brain Stack",
    description: "Gemini + OmniRoute + SVS-Cyber AI combined",
    available: false,
    badge: "Development",
  },
];

// ─── Context type ─────────────────────────────────────────────────────────────

interface StaiGlobalStateType {
  // File upload state
  uploadedFiles: UploadedFileState[];
  setUploadedFiles: (files: UploadedFileState[]) => void;
  addUploadedFile: (file: UploadedFileState) => void;
  removeUploadedFile: (index: number) => void;
  updateUploadedFile: (
    index: number,
    updates: Partial<UploadedFileState>,
  ) => void;
  getTotalTokens: () => number;
  isUploadingFiles: boolean;

  // Chat mode
  chatMode: ChatMode;
  setChatMode: (mode: ChatMode) => void;
  chatModeAccessResolved: boolean;
  paidAgentOnlyActive: boolean;
  freeDesktopAgentOnlyActive: boolean;

  // Sidebar
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  sidebarContent: SidebarContent | null;
  setSidebarContent: (content: SidebarContent | null) => void;
  chatSidebarOpen: boolean;
  setChatSidebarOpen: (open: boolean) => void;
  optimisticChatId: string | null;
  setOptimisticChatId: (chatId: string | null) => void;
  activeProjectId: string | null;
  setActiveProjectId: (projectId: string | null) => void;

  // Todos
  todos: Todo[];
  setTodos: (todos: Todo[]) => void;
  mergeTodos: (todos: Todo[]) => void;
  replaceAssistantTodos: (todos: Todo[], sourceMessageId?: string) => void;

  // UI
  isTodoPanelExpanded: boolean;
  setIsTodoPanelExpanded: (expanded: boolean) => void;

  // Subscription (SVS-Cyber always "pro")
  subscription: SubscriptionTier;
  isCheckingProPlan: boolean;
  localConnections: unknown[];

  // Model
  selectedModel: SelectedModel;
  setSelectedModel: (model: SelectedModel) => void;

  // Sandbox
  sandboxPreference: SandboxPreference;
  setSandboxPreference: (pref: SandboxPreference) => void;
  hasLocalSandbox: boolean;
  desktopBridgeStatus: "connected" | "disconnected" | "connecting";
  defaultLocalSandboxPreference: SandboxPreference;

  // Agent permission
  agentPermissionMode: AgentPermissionMode;
  setAgentPermissionMode: (mode: AgentPermissionMode) => void;

  // Message queue
  messageQueue: QueuedMessage[];
  updateQueuedMessage: (id: string, content: string) => void;
  setEditingQueuedMessageId: (id: string | null) => void;
  removeQueuedMessage: (id: string) => void;
  queueBehavior: QueueBehavior;
  setQueueBehavior: (behavior: QueueBehavior) => void;

  // Misc
  isMobile: boolean;
  fileMessageParts: unknown[];
}

// ─── Context ──────────────────────────────────────────────────────────────────

const StaiGlobalStateContext = createContext<StaiGlobalStateType | undefined>(
  undefined,
);

// ─── Provider ─────────────────────────────────────────────────────────────────

function StaiGlobalStateInner({ children }: { children: ReactNode }) {
  const { clearInput } = useComposerActions();

  const [uploadedFiles, setUploadedFiles] = useState<UploadedFileState[]>([]);
  const [chatMode, setChatMode] = useState<ChatMode>("agent");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarContent, setSidebarContent] =
    useState<SidebarContent | null>(null);
  const [chatSidebarOpen, setChatSidebarOpen] = useState(true);
  const [optimisticChatId, setOptimisticChatId] = useState<string | null>(null);
  const [activeProjectId, setActiveProjectId] = useState<string | null>(null);
  const [todos, setTodos] = useState<Todo[]>([]);
  const [isTodoPanelExpanded, setIsTodoPanelExpanded] = useState(false);
  const [selectedModel, setSelectedModel] = useState<SelectedModel>("auto");
  const [sandboxPreference, setSandboxPreference] =
    useState<SandboxPreference>("local");
  const [agentPermissionMode, setAgentPermissionMode] =
    useState<AgentPermissionMode>("normal");
  const [messageQueue, setMessageQueue] = useState<QueuedMessage[]>([]);
  const [queueBehavior, setQueueBehavior] = useState<QueueBehavior>("queue");

  const addUploadedFile = useCallback((file: UploadedFileState) => {
    setUploadedFiles((prev) => [...prev, file]);
  }, []);

  const removeUploadedFile = useCallback((index: number) => {
    setUploadedFiles((prev) => prev.filter((_, i) => i !== index));
  }, []);

  const updateUploadedFile = useCallback(
    (index: number, updates: Partial<UploadedFileState>) => {
      setUploadedFiles((prev) =>
        prev.map((f, i) => (i === index ? { ...f, ...updates } : f)),
      );
    },
    [],
  );

  const getTotalTokens = useCallback(() => {
    return uploadedFiles.reduce((sum, f) => sum + (f.tokens ?? 0), 0);
  }, [uploadedFiles]);

  const mergeTodos = useCallback((newTodos: Todo[]) => {
    setTodos((prev) => {
      const map = new Map(prev.map((t) => [t.id, t]));
      newTodos.forEach((t) => map.set(t.id, { ...map.get(t.id), ...t }));
      return Array.from(map.values());
    });
  }, []);

  const replaceAssistantTodos = useCallback((newTodos: Todo[]) => {
    setTodos(newTodos);
  }, []);

  const updateQueuedMessage = useCallback((id: string, content: string) => {
    setMessageQueue((prev) =>
      prev.map((m) => (m.id === id ? { ...m, content } : m)),
    );
  }, []);

  const setEditingQueuedMessageId = useCallback(
    (_id: string | null) => {
      // no-op for now — queue editing not needed in SVS-Cyber
    },
    [],
  );

  const removeQueuedMessage = useCallback((id: string) => {
    setMessageQueue((prev) => prev.filter((m) => m.id !== id));
  }, []);

  const value = useMemo<StaiGlobalStateType>(
    () => ({
      uploadedFiles,
      setUploadedFiles,
      addUploadedFile,
      removeUploadedFile,
      updateUploadedFile,
      getTotalTokens,
      isUploadingFiles: false,

      chatMode,
      setChatMode,
      chatModeAccessResolved: true,
      paidAgentOnlyActive: false,
      freeDesktopAgentOnlyActive: false,

      sidebarOpen,
      setSidebarOpen,
      sidebarContent,
      setSidebarContent,
      chatSidebarOpen,
      setChatSidebarOpen,
      optimisticChatId,
      setOptimisticChatId,
      activeProjectId,
      setActiveProjectId,

      todos,
      setTodos,
      mergeTodos,
      replaceAssistantTodos,

      isTodoPanelExpanded,
      setIsTodoPanelExpanded,

      // SVS-Cyber is always "pro" — no paywalls
      subscription: "pro",
      isCheckingProPlan: false,
      localConnections: [],

      selectedModel,
      setSelectedModel,

      sandboxPreference,
      setSandboxPreference,
      hasLocalSandbox: true,
      desktopBridgeStatus: "connected",
      defaultLocalSandboxPreference: "local",

      agentPermissionMode,
      setAgentPermissionMode,

      messageQueue,
      updateQueuedMessage,
      setEditingQueuedMessageId,
      removeQueuedMessage,
      queueBehavior,
      setQueueBehavior,

      isMobile: false,
      fileMessageParts: [],
    }),
    [
      uploadedFiles,
      addUploadedFile,
      removeUploadedFile,
      updateUploadedFile,
      getTotalTokens,
      chatMode,
      sidebarOpen,
      sidebarContent,
      chatSidebarOpen,
      optimisticChatId,
      activeProjectId,
      todos,
      mergeTodos,
      replaceAssistantTodos,
      isTodoPanelExpanded,
      selectedModel,
      sandboxPreference,
      agentPermissionMode,
      messageQueue,
      updateQueuedMessage,
      setEditingQueuedMessageId,
      removeQueuedMessage,
      queueBehavior,
    ],
  );

  return (
    <StaiGlobalStateContext.Provider value={value}>
      {children}
    </StaiGlobalStateContext.Provider>
  );
}

export function StaiGlobalStateProvider({ children }: { children: ReactNode }) {
  return (
    <ComposerStateProvider>
      <StaiGlobalStateInner>{children}</StaiGlobalStateInner>
    </ComposerStateProvider>
  );
}

// ─── Hooks ────────────────────────────────────────────────────────────────────

export function useGlobalState(): StaiGlobalStateType {
  const ctx = useContext(StaiGlobalStateContext);
  if (!ctx) {
    throw new Error("useGlobalState must be used within StaiGlobalStateProvider");
  }
  return ctx;
}

// Re-export useAuth stub so HackerAI components that call useAuth() still work
export function useAuth() {
  return {
    user: {
      id: "svs-cyber-local",
      email: "local@svs-cyber",
      firstName: "SVS",
      lastName: "Cyber",
      locale: "en",
    },
    loading: false,
  };
}

export function useAccessToken() {
  return { accessToken: null, loading: false };
}
