"use client";

import { useEffect, useRef } from "react";
import {
  openStaiEvents,
  type StaiAgentEvent,
  type StaiEventStreamHandle,
} from "@/lib/stai-api";

export interface NormalizedTextPart {
  type: "text";
  text: string;
}

export interface NormalizedReasoningPart {
  type: "reasoning";
  activity: string;
}

export interface NormalizedToolPart {
  type: "tool";
  toolCallId: string;
  toolName: string;
  state:
    | "input-streaming"
    | "input-available"
    | "approval-requested"
    | "approval-responded"
    | "output-available"
    | "output-error";
  input?: Record<string, unknown>;
  output?: unknown;
  progress?: number;
  elapsedSeconds?: number;
  errorText?: string;
  approval?: { requestId?: string; approved?: boolean };
}

export type NormalizedMessagePart =
  | NormalizedTextPart
  | NormalizedReasoningPart
  | NormalizedToolPart;

export interface NormalizedChatEntry {
  id: string;
  role: "user" | "assistant" | "event";
  parts: NormalizedMessagePart[];
  timestamp: string;
  finishedAt?: string;
  animate?: boolean;
}

export interface NormalizedActivityEvent {
  id: string;
  label: string;
  detail: string;
  status: "running" | "completed" | "failed" | "info";
  startedAt?: number;
}

export interface UseSvsEventStreamOpts {
  onNormalizedEvent: (rawEvent: StaiAgentEvent) => void;
  onConnectionChange: (
    state: "connecting" | "connected" | "disconnected",
  ) => void;
}

export function useSvsEventStream(
  sessionId: string | null,
  opts: UseSvsEventStreamOpts,
): void {
  const seenEventIdsRef = useRef<Set<string>>(new Set());
  const optsRef = useRef<UseSvsEventStreamOpts>(opts);
  const sessionIdRef = useRef<string | null>(sessionId);

  useEffect(() => {
    optsRef.current = opts;
  }, [opts]);

  useEffect(() => {
    sessionIdRef.current = sessionId;
  }, [sessionId]);

  useEffect(() => {
    if (sessionId === null) return undefined;

    let handle: StaiEventStreamHandle | null = null;
    let mounted = true;

    optsRef.current.onConnectionChange("connecting");

    handle = openStaiEvents(
      (event) => {
        if (!mounted) return;
        if (
          sessionIdRef.current !== null &&
          event.session_id !== sessionIdRef.current
        ) {
          return;
        }
        if (event.event_id && seenEventIdsRef.current.has(event.event_id)) {
          return;
        }
        if (event.event_id) {
          seenEventIdsRef.current.add(event.event_id);
        }
        if (process.env.NODE_ENV === "development") {
          console.debug("[svs-event]", event.type, {
            event_id: event.event_id,
            session_id: event.session_id,
            message: event.message,
            data: event.data,
          });
        }
        optsRef.current.onNormalizedEvent(event);
      },
      () => {
        if (!mounted) return;
        optsRef.current.onConnectionChange("disconnected");
      },
      () => {
        if (!mounted) return;
        optsRef.current.onConnectionChange("connected");
      },
      () => {
        if (!mounted) return;
        optsRef.current.onConnectionChange("disconnected");
      },
    );

    return () => {
      mounted = false;
      if (handle !== null) {
        handle.close();
        handle = null;
      }
    };
  }, [sessionId]);
}
