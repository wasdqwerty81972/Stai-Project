import { useState, type FormEvent } from "react";
import { Bot, LoaderCircle, MessageCircle, RefreshCw, Send, ShieldAlert, Sparkles } from "lucide-react";
import type {
  AgentHistory,
  AgentReply,
  DetectionRecord,
  TriageRecord,
  SensorWarning,
} from "../protection-api";
import { DetectionRow } from "./DetectionRow";
import { EmptyState } from "./EmptyState";
import { PageHeading } from "./PageHeading";

export function AgentView({
  threats,
  threatsError,
  selectedDetection,
  onSelectDetection,
  triage,
  triageLoading,
  triageError,
  onRetryTriage,
  history,
  historyError,
  onSend,
  sensorWarnings,
}: {
  threats: DetectionRecord[] | null;
  threatsError: string | null;
  selectedDetection: DetectionRecord | null;
  onSelectDetection: (detection: DetectionRecord) => void;
  triage: TriageRecord | null;
  triageLoading: boolean;
  triageError: string | null;
  onRetryTriage: () => Promise<void>;
  history: AgentHistory | null;
  historyError: string | null;
  onSend: (message: string) => Promise<AgentReply>;
  sensorWarnings: SensorWarning[];
}) {
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const [reply, setReply] = useState<string | null>(null);

  const send = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const message = draft.trim();
    if (!message || !selectedDetection) return;
    setSending(true);
    setSendError(null);
    setReply(null);
    try {
      const result = await onSend(message);
      if (result.tool_calls.length > 0 || result.response_action !== null) {
        throw new Error("The agent response included an unsupported action and was not displayed.");
      }
      setReply(result.message);
      setDraft("");
    } catch (cause) {
      setSendError(cause instanceof Error ? cause.message : "Unable to send this question.");
    } finally {
      setSending(false);
    }
  };

  return (
    <>
      <PageHeading
        eyebrow="LEVEL 2 INVESTIGATION"
        title="AI Agent"
        description="Review stored analysis for a detection and ask evidence-scoped follow-up questions."
      />
      <section className="panel sensor-ai-review-panel">
        <div className="panel-heading">
          <div><div className="eyebrow">CYBEROS SENSOR TRIAGE</div><h2>Autonomous warning review</h2></div>
          <span className="panel-icon"><Sparkles size={18} aria-hidden="true" /></span>
        </div>
        {sensorWarnings.length === 0 ? (
          <EmptyState title="No sensor warnings" description="Rule-matched warnings are saved by the Windows service and reviewed by the configured AI provider when available." />
        ) : (
          <div className="sensor-warning-list">
            {sensorWarnings.map((warning) => (
              <article className="sensor-warning" key={warning.event_id}>
                <div className="sensor-warning-heading"><strong>{warning.summary}</strong><span>{warning.ai_state.replaceAll("_", " ")}</span></div>
                <p>{warning.ai_analysis || "AI analysis is queued or unavailable; the warning remains stored for retry."}</p>
                <div className="sensor-warning-meta">
                  {warning.severity} · sensors {warning.sensor_ids.join(", ")} · protection {warning.protection_state}
                  {warning.classification ? ` · AI ${warning.classification}` : ""}
                  {warning.ai_confidence !== null && warning.ai_confidence !== undefined ? ` (${Math.round(warning.ai_confidence * 100)}%)` : ""}
                  {warning.protection_action ? ` · ${warning.protection_action.replaceAll("_", " ")}` : ""}
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
      <div className="agent-layout">
        <section className="panel agent-detections-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">ESCALATED DETECTIONS</div>
              <h2>Review queue</h2>
            </div>
            <span className="panel-icon"><Bot size={18} aria-hidden="true" /></span>
          </div>
          {threatsError ? (
            <div role="alert" className="inline-alert error-alert">{threatsError}</div>
          ) : threats === null ? (
            <div className="loading-row"><span className="spinner" /> Loading detections…</div>
          ) : threats.length === 0 ? (
            <EmptyState title="No detection to review" description="The local service has not recorded an item for agent review." />
          ) : (
            <div className="agent-detection-list">
              {threats.map((detection) => (
                <DetectionRow
                  detection={detection}
                  key={detection.detection_id}
                  onOpen={onSelectDetection}
                />
              ))}
            </div>
          )}
        </section>

        <section className="panel agent-analysis-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">STORED INVESTIGATION</div>
              <h2>Analysis & follow-up</h2>
            </div>
            <span className="panel-icon"><Sparkles size={18} aria-hidden="true" /></span>
          </div>

          {!selectedDetection ? (
            <EmptyState title="Select a detection" description="Choose a recorded item to view its analysis and ask a follow-up question." />
          ) : (
            <>
              <div className="selected-detection">
                <span className="detection-symbol" aria-hidden="true"><ShieldAlert size={17} /></span>
                <div><strong>{selectedDetection.file_path || "Path not reported"}</strong><span>Detection {selectedDetection.detection_id}</span></div>
              </div>

              {triageError ? (
                <div role="alert" className="inline-alert error-alert agent-error">
                  <span>{triageError}</span>
                  <button className="text-button" onClick={() => void onRetryTriage()} type="button">Retry analysis <RefreshCw size={13} /></button>
                </div>
              ) : triageLoading ? (
                <div className="loading-row"><span className="spinner" /> Loading stored analysis…</div>
              ) : triage ? (
                <div className="triage-card">
                  <div className="triage-status"><span className="triage-dot" /> {triage.state}</div>
                  <h3>Summary</h3>
                  <p>{triage.summary || triage.error || "No analysis summary was stored for this detection yet."}</p>
                  {(triage.recommendations ?? []).length > 0 && (
                    <>
                      <h3>Recommendations</h3>
                      <ul>{(triage.recommendations ?? []).map((item) => <li key={item}>{item}</li>)}</ul>
                    </>
                  )}
                  {historyError && <p className="helper-note">Conversation history is unavailable. You can still ask a follow-up question.</p>}
                  {history?.messages.map((message, index) => (
                    <div className={`conversation-message message-${message.role}`} key={`${message.role}-${index}`}>
                      <span>{message.role === "assistant" ? "AI Agent" : "You"}</span>
                      <p>{message.content}</p>
                    </div>
                  ))}
                  {reply && (
                    <div className="conversation-message message-assistant" role="status">
                      <span>AI Agent</span>
                      <p>{reply}</p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="triage-empty">
                  <MessageCircle size={19} aria-hidden="true" />
                  <p>No stored analysis is available for this detection yet.</p>
                  <button className="button button-secondary" onClick={() => void onRetryTriage()} type="button">Request analysis</button>
                </div>
              )}

              <form className="agent-composer" onSubmit={(event) => void send(event)}>
                <label htmlFor="agent-question">Ask about this detection</label>
                <div className="composer-control">
                  <textarea
                    id="agent-question"
                    aria-label="Ask about this detection"
                    onChange={(event) => setDraft(event.target.value)}
                    placeholder="Ask about the recorded evidence…"
                    rows={2}
                    value={draft}
                  />
                  <button className="button button-primary send-button" disabled={!draft.trim() || sending} type="submit" aria-label="Send question">
                    {sending ? <LoaderCircle size={16} className="spin" /> : <Send size={16} />}
                    <span>{sending ? "Sending" : "Send"}</span>
                  </button>
                </div>
                {sendError && <div role="alert" className="inline-alert error-alert">{sendError}</div>}
                <p className="composer-note">If cloud triage is enabled by your administrator, Google Gemini receives minimized detection metadata, your question, and bounded chat history. Redaction is best effort; do not type secrets, personal information, or file paths. The agent cannot change verdicts or run commands.</p>
              </form>
            </>
          )}
        </section>
      </div>
    </>
  );
}
