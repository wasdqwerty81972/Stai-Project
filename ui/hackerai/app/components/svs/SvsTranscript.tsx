"use client";

import { useState, type Ref } from "react";
import {
  AlertCircle,
  BrainIcon,
  CheckCircle2,
  Clock3,
  Wrench,
} from "lucide-react";
import { MemoizedMarkdown } from "../MemoizedMarkdown";
import {
  WorkedFor,
  WorkedForContent,
  WorkedForTrigger,
} from "@/components/ai-elements/worked-for";

export type SvsTranscriptPart =
  | { type: "text"; text: string }
  | { type: "reasoning"; activity: string }
  | {
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
    };

export interface SvsTranscriptEntry {
  id: string;
  role: "user" | "assistant" | "event";
  timestamp: string;
  finishedAt?: string;
  animate?: boolean;
  parts: SvsTranscriptPart[];
}

export interface SvsTranscriptProps {
  entries: SvsTranscriptEntry[];
  running: boolean;
  error: string | null;
  sessionId: string;
  onApproval: (requestId: string, approved: boolean) => void | Promise<void>;
  bottomRef: Ref<HTMLDivElement>;
}

type ToolPart = Extract<SvsTranscriptPart, { type: "tool" }>;

function formatEvidence(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function ToolEvidence({
  part,
  onApproval,
}: {
  part: ToolPart;
  onApproval: SvsTranscriptProps["onApproval"];
}) {
  const [pending, setPending] = useState(false);
  const [decision, setDecision] = useState<boolean | null>(null);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const failed = part.state === "output-error";
  const completed = part.state === "output-available";
  const awaitingApproval = part.state === "approval-requested";
  const requestId = part.approval?.requestId;
  const knownDecision = part.approval?.approved ?? decision;
  const status = failed
    ? "failed"
    : completed
      ? "completed"
      : awaitingApproval
        ? "awaiting approval"
        : part.state === "approval-responded"
          ? "approval response sent"
          : "running";
  const StatusIcon = failed ? AlertCircle : completed ? CheckCircle2 : Clock3;

  async function respond(approved: boolean) {
    if (!requestId || pending) return;
    setPending(true);
    setApprovalError(null);
    try {
      await onApproval(requestId, approved);
      setDecision(approved);
    } catch (error) {
      setApprovalError(
        error instanceof Error
          ? error.message
          : "Could not send approval response.",
      );
    } finally {
      setPending(false);
    }
  }

  return (
    <div
      className="my-2 min-w-0 overflow-hidden rounded-xl border border-border bg-muted/20 text-sm"
      data-testid={`tool-part-${part.toolCallId}`}
    >
      <div className="flex min-w-0 items-center gap-2 px-3 py-2.5">
        <Wrench
          aria-hidden="true"
          className="size-4 shrink-0 text-muted-foreground"
        />
        <span className="min-w-0 flex-1 break-words font-medium">
          {part.toolName}
        </span>
        <span
          className={`inline-flex shrink-0 items-center gap-1 text-xs ${failed ? "text-destructive" : completed ? "text-emerald-400" : "text-muted-foreground"}`}
        >
          <StatusIcon aria-hidden="true" className="size-3.5" />
          {status}
        </span>
      </div>

      {part.input && (
        <div className="border-t border-border px-3 py-2">
          <div className="mb-1 text-xs font-medium text-muted-foreground">
            Input
          </div>
          <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words font-mono text-xs">
            {formatEvidence(part.input)}
          </pre>
        </div>
      )}
      {(part.output !== undefined || part.errorText) && (
        <div className="border-t border-border px-3 py-2">
          <div
            className={`mb-1 text-xs font-medium ${failed ? "text-destructive" : "text-muted-foreground"}`}
          >
            {failed ? "Error" : "Output"}
          </div>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words font-mono text-xs">
            {formatEvidence(part.errorText ?? part.output)}
          </pre>
        </div>
      )}
      {part.approval && (
        <div className="border-t border-border px-3 py-2 text-xs">
          {knownDecision !== null && knownDecision !== undefined ? (
            <span>{knownDecision ? "Approved." : "Denied."}</span>
          ) : pending ? (
            <span role="status">Sending approval response...</span>
          ) : awaitingApproval ? (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span>Approval requested for this action.</span>
              {requestId ? (
                <span className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => void respond(false)}
                    className="rounded border border-border px-2 py-1 hover:bg-muted"
                  >
                    Deny
                  </button>
                  <button
                    type="button"
                    onClick={() => void respond(true)}
                    className="rounded bg-foreground px-2 py-1 text-background hover:opacity-80"
                  >
                    Allow
                  </button>
                </span>
              ) : (
                <span className="text-muted-foreground">
                  Approval controls unavailable.
                </span>
              )}
            </div>
          ) : (
            <span>Approval response sent.</span>
          )}
          {approvalError && (
            <div role="alert" className="mt-2 text-destructive">
              {approvalError}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AssistantTurn({
  entry,
  running,
  onApproval,
}: {
  entry: SvsTranscriptEntry;
  running: boolean;
  onApproval: SvsTranscriptProps["onApproval"];
}) {
  const workParts = entry.parts.filter(
    (part) => part.type === "reasoning" || part.type === "tool",
  );
  const textParts = entry.parts.filter((part) => part.type === "text");
  const attentionNeeded = workParts.some(
    (part) =>
      part.type === "tool" &&
      (part.state === "output-error" || part.state === "approval-requested"),
  );
  const startedAt = Date.parse(entry.timestamp);
  const finishedAt = entry.finishedAt ? Date.parse(entry.finishedAt) : NaN;
  const durationMs =
    Number.isFinite(startedAt) && Number.isFinite(finishedAt)
      ? Math.max(0, finishedAt - startedAt)
      : undefined;

  return (
    <div className="w-full min-w-0 space-y-3 text-foreground">
      {workParts.length > 0 && (
        <WorkedFor
          hasWork
          defaultOpen={running || attentionNeeded || textParts.length === 0}
          isTiming={running}
        >
          <WorkedForTrigger
            isTiming={running}
            startedAt={Number.isFinite(startedAt) ? startedAt : undefined}
            durationMs={durationMs}
          />
          <WorkedForContent>
            {workParts.map((part, index) => {
              if (part.type === "tool") {
                return (
                  <ToolEvidence
                    key={`${entry.id}-${part.toolCallId}-${index}`}
                    part={part}
                    onApproval={onApproval}
                  />
                );
              }
              if (workParts[index - 1]?.type === "reasoning") return null;
              const activities: string[] = [];
              for (let next = index; next < workParts.length; next++) {
                const candidate = workParts[next];
                if (candidate?.type !== "reasoning") break;
                if (candidate.activity.trim())
                  activities.push(candidate.activity);
              }
              return activities.length > 0 ? (
                <div
                  key={`${entry.id}-activity-${index}`}
                  className="flex gap-2 rounded-lg border border-border/70 bg-muted/10 px-3 py-2 text-sm text-muted-foreground"
                >
                  <BrainIcon
                    aria-hidden="true"
                    className="mt-0.5 size-4 shrink-0"
                  />
                  <div className="min-w-0 space-y-2 whitespace-pre-wrap break-words">
                    {activities.map((activity, activityIndex) => (
                      <div key={activityIndex}>{activity}</div>
                    ))}
                  </div>
                </div>
              ) : null;
            })}
          </WorkedForContent>
        </WorkedFor>
      )}
      {textParts.map((part, index) => (
        <div key={index} className="prose max-w-none min-w-0 dark:prose-invert">
          <MemoizedMarkdown content={part.text} />
        </div>
      ))}
    </div>
  );
}

export function SvsTranscript({
  entries,
  running,
  error,
  sessionId,
  onApproval,
  bottomRef,
}: SvsTranscriptProps) {
  return (
    <div
      className="mx-auto flex w-full max-w-[768px] flex-col gap-6"
      aria-label="Investigation transcript"
      data-session-id={sessionId}
    >
      {entries.length === 0 && !running && (
        <div className="flex min-h-[45vh] items-center justify-center text-center text-sm text-muted-foreground">
          What investigation are we running?
        </div>
      )}
      {entries.map((entry, entryIndex) => (
        <article
          key={entry.id}
          className={`flex w-full min-w-0 flex-col ${entry.role === "user" ? "items-end" : "items-start"}`}
        >
          {entry.role === "user" ? (
            <div className="max-w-[85%] rounded-[18px] rounded-se-lg border border-border bg-secondary px-4 py-2 text-primary-foreground">
              {entry.parts.map((part, index) =>
                part.type === "text" ? (
                  <div key={index} className="whitespace-pre-wrap break-words">
                    {part.text}
                  </div>
                ) : null,
              )}
            </div>
          ) : (
            <AssistantTurn
              entry={entry}
              running={running && entryIndex === entries.length - 1}
              onApproval={onApproval}
            />
          )}
        </article>
      ))}
      {running && entries.at(-1)?.role !== "assistant" && (
        <div
          role="status"
          className="flex items-center gap-2 text-sm text-muted-foreground"
        >
          <BrainIcon aria-hidden="true" className="size-4" />
          Thinking...
        </div>
      )}
      {error && (
        <div role="alert" className="text-sm text-destructive">
          {error}
        </div>
      )}
      <div ref={bottomRef} />
    </div>
  );
}
