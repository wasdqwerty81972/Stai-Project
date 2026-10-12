"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { Bot, Send, Loader2, Info } from "lucide-react";
import {
  getAgentHistory,
  getTriage,
  sendAgentMessage,
  type ProtectionAgentMessage,
  type ProtectionTriage,
  type ThreatRecord,
} from "@/lib/stai-protection-api";
import { ActionBadge, AsyncState, formatTimestamp, shortHash } from "./ProtectionPrimitives";

interface Props {
  threats: ThreatRecord[];
  loading: boolean;
  error: string | null;
}

function sessionIdFor(detectionId: string | null): string {
  return detectionId ? `protection-triage-${detectionId}` : "protection-triage";
}

export function ProtectionAgent({ threats, loading, error }: Props) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [triage, setTriage] = useState<ProtectionTriage | null>(null);
  const [triageError, setTriageError] = useState<string | null>(null);
  const [triageLoading, setTriageLoading] = useState(false);
  const [messages, setMessages] = useState<ProtectionAgentMessage[]>([]);
  const [historyNote, setHistoryNote] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);

  // Auto-select the first (escalated-first) detection once threats load.
  const ordered = [...threats].sort(
    (a, b) => Number(b.triage_enqueued) - Number(a.triage_enqueued),
  );
  useEffect(() => {
    if (selectedId === null && ordered.length > 0) {
      setSelectedId(ordered[0].detection_id);
    }
  }, [ordered, selectedId]);

  const selected = threats.find((t) => t.detection_id === selectedId) ?? null;
  const sessionId = sessionIdFor(selectedId);

  const loadDetection = useCallback(async (detectionId: string) => {
    setTriage(null);
    setTriageError(null);
    setMessages([]);
    setHistoryNote(null);
    setSendError(null);

    setTriageLoading(true);
    try {
      setTriage(await getTriage(detectionId));
    } catch (err) {
      setTriageError(
        err instanceof Error
          ? err.message
          : "Automated triage summary is unavailable.",
      );
    } finally {
      setTriageLoading(false);
    }

    try {
      const history = await getAgentHistory(sessionIdFor(detectionId));
      setMessages(history.messages ?? []);
    } catch (err) {
      setHistoryNote(
        err instanceof Error
          ? `Conversation history unavailable: ${err.message}`
          : "Conversation history unavailable.",
      );
    }
  }, []);

  useEffect(() => {
    if (selectedId) void loadDetection(selectedId);
  }, [selectedId, loadDetection]);

  async function handleSend(event: FormEvent) {
    event.preventDefault();
    const text = draft.trim();
    if (!text || sending) return;
    setSendError(null);
    setSending(true);
    setMessages((prev) => [...prev, { role: "user", message: text }]);
    setDraft("");
    try {
      const response = await sendAgentMessage(sessionId, text, selectedId);
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          message: response.message,
          response_action: response.response_action,
        },
      ]);
    } catch (err) {
      setSendError(
        err instanceof Error ? err.message : "The protection agent did not respond.",
      );
    } finally {
      setSending(false);
    }
  }

  return (
    <section aria-label="AI agent" className="grid gap-4 lg:grid-cols-[18rem_1fr]">
      {/* Escalated detections */}
      <div className="rounded-xl border border-border bg-card/40 p-4">
        <div className="flex items-center gap-2">
          <Bot className="size-4 text-cyan-300" aria-hidden="true" />
          <h3 className="text-sm font-semibold text-foreground">
            Escalated detections
          </h3>
        </div>
        <div className="mt-3">
          {loading ? (
            <AsyncState kind="loading" title="Loading detections…" />
          ) : error ? (
            <AsyncState kind="error" title="Detections unavailable" detail={error} />
          ) : ordered.length === 0 ? (
            <AsyncState
              kind="empty"
              title="Nothing escalated"
              detail="Detections escalated for Level 2 review will appear here."
            />
          ) : (
            <ul className="space-y-1.5" aria-label="Detections">
              {ordered.map((threat) => {
                const active = threat.detection_id === selectedId;
                return (
                  <li key={threat.detection_id}>
                    <button
                      type="button"
                      aria-current={active ? "true" : undefined}
                      onClick={() => setSelectedId(threat.detection_id)}
                      className={`w-full rounded-md border px-2.5 py-2 text-left transition-colors focus-visible:outline-2 focus-visible:outline-ring ${
                        active
                          ? "border-cyan-500/50 bg-cyan-500/10"
                          : "border-border bg-background/40 hover:bg-accent"
                      }`}
                    >
                      <span className="flex items-center justify-between gap-2">
                        <span className="truncate text-sm font-medium text-foreground">
                          {threat.rule_id}
                        </span>
                        <ActionBadge action={threat.action} />
                      </span>
                      <span className="mt-0.5 block truncate text-[11px] text-muted-foreground">
                        {threat.severity} ·{" "}
                        {threat.file_path || threat.file_type || "path withheld"}
                      </span>
                      {threat.triage_enqueued ? (
                        <span className="mt-0.5 block text-[11px] text-cyan-300">
                          Escalated for triage
                        </span>
                      ) : null}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>

      {/* Triage + chat */}
      <div className="flex flex-col gap-4">
        <p className="flex items-start gap-2 rounded-lg border border-border bg-background/40 px-3 py-2 text-[11px] text-muted-foreground">
          <Info className="mt-0.5 size-3.5 shrink-0 text-cyan-300" aria-hidden="true" />
          <span>
            Investigation-scoped assistant. It explains this detection and the
            stored evidence only — it cannot change the Level 1 verdict, update
            signatures, or take privileged system actions.
          </span>
        </p>

        {selected ? (
          <div className="rounded-xl border border-border bg-card/40 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold text-foreground">
                {selected.rule_id}
              </h3>
              <ActionBadge action={selected.action} />
              <span className="text-[11px] uppercase text-muted-foreground">
                {selected.severity} · confidence {selected.confidence}
              </span>
            </div>
            <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
              <span className="break-all">
                {selected.file_path || selected.file_type || "path withheld"}
              </span>
              <span>sha256 {shortHash(selected.sha256)}</span>
              <span>{formatTimestamp(selected.created_at)}</span>
            </div>

            <div className="mt-3 border-t border-border/60 pt-3">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Level 2 triage
              </h4>
              {triageLoading ? (
                <p className="mt-2 inline-flex items-center gap-2 text-xs text-muted-foreground">
                  <Loader2 className="size-3.5 motion-safe:animate-spin" aria-hidden="true" />
                  Loading triage…
                </p>
              ) : triage ? (
                <div className="mt-2 space-y-2">
                  <p className="text-sm text-foreground">{triage.summary}</p>
                  {triage.recommendations.length > 0 ? (
                    <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted-foreground">
                      {triage.recommendations.map((rec, index) => (
                        <li key={index}>{rec}</li>
                      ))}
                    </ul>
                  ) : null}
                  <p className="text-[11px] text-muted-foreground">
                    State: {triage.state}
                  </p>
                </div>
              ) : (
                <p className="mt-2 text-xs text-amber-300">
                  {triageError ||
                    "No stored triage for this detection yet."}
                </p>
              )}
            </div>
          </div>
        ) : null}

        {/* Chat thread */}
        <div className="flex min-h-[14rem] flex-col rounded-xl border border-border bg-card/40">
          <div className="flex-1 space-y-3 overflow-y-auto p-4" aria-label="Conversation">
            {historyNote ? (
              <p className="text-[11px] text-muted-foreground">{historyNote}</p>
            ) : null}
            {messages.length === 0 && !historyNote ? (
              <p className="text-xs text-muted-foreground">
                Ask the agent to explain this detection or its evidence.
              </p>
            ) : null}
            {messages.map((msg, index) => (
              <div
                key={index}
                className={msg.role === "user" ? "text-right" : "text-left"}
              >
                <span
                  className={`inline-block max-w-[90%] whitespace-pre-wrap rounded-lg px-3 py-2 text-sm ${
                    msg.role === "user"
                      ? "bg-cyan-500/15 text-cyan-50"
                      : "bg-background/60 text-foreground"
                  }`}
                >
                  {msg.message}
                </span>
                {msg.response_action ? (
                  <p className="mt-1 text-[11px] text-amber-300">
                    Proposed action (requires human approval): {msg.response_action}
                  </p>
                ) : null}
              </div>
            ))}
          </div>

          {sendError ? (
            <p role="alert" className="mx-4 mb-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {sendError}
            </p>
          ) : null}

          <form onSubmit={handleSend} className="flex items-end gap-2 border-t border-border/60 p-3">
            <textarea
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey) {
                  event.preventDefault();
                  void handleSend(event);
                }
              }}
              rows={2}
              aria-label="Ask a follow-up question about this detection"
              placeholder="Ask a follow-up question about this detection"
              className="min-h-[2.5rem] flex-1 resize-none rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus:ring-2 focus:ring-ring"
            />
            <button
              type="submit"
              disabled={sending || draft.trim() === ""}
              className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-sm font-medium text-cyan-100 transition-colors hover:bg-cyan-500/20 focus-visible:outline-2 focus-visible:outline-ring disabled:cursor-not-allowed disabled:opacity-50"
            >
              {sending ? (
                <Loader2 className="size-4 motion-safe:animate-spin" aria-hidden="true" />
              ) : (
                <Send className="size-4" aria-hidden="true" />
              )}
              Send
            </button>
          </form>
        </div>
      </div>
    </section>
  );
}
