import {
  applyEvent,
  reconcileEvents,
  type ChatEntry,
} from "../StaiChatWorkspace";
import type { StaiAgentEvent } from "@/lib/stai-api";

const start = Date.parse("2026-09-27T10:00:00.000Z");

function event(
  id: string,
  type: string,
  second: number,
  message = "",
  options: { tool?: string; data?: Record<string, unknown> } = {},
): StaiAgentEvent {
  return {
    event_id: id,
    type,
    timestamp: new Date(start + second * 1000).toISOString(),
    session_id: "session-1",
    investigation_id: "run-1",
    source: "agent",
    correlation_id: "",
    entity_ids: [],
    tool: options.tool ?? null,
    agent: null,
    status: "",
    message,
    data: options.data ?? {},
  };
}

function reduce(events: StaiAgentEvent[]): ChatEntry[] {
  return events.reduce((entries, item) => applyEvent(entries, item), [] as ChatEntry[]);
}

describe("SVS transcript event reduction", () => {
  it("keeps reasoning, tool evidence, and response in one assistant turn", () => {
    const entries = reduce([
      event("user-1", "user_message", 0, "Scan this host"),
      event("reason-1", "agent_reasoning", 1, "Checking ports"),
      event("tool-1", "tool_started", 2, "", {
        tool: "Port scanner",
        data: { tool_call_id: "call-1", input: { target: "host" } },
      }),
      event("tool-2", "tool_completed", 3, "", {
        tool: "Port scanner",
        data: { tool_call_id: "call-1", output: { open: [443] } },
      }),
      event("answer-1", "response", 4, "Port 443 is open."),
    ]);

    expect(entries).toHaveLength(2);
    expect(entries[1]?.role).toBe("assistant");
    expect(entries[1]?.parts.map((part) => part.type)).toEqual([
      "reasoning",
      "tool",
      "text",
    ]);
    expect(entries[1]?.parts[1]).toMatchObject({
      type: "tool",
      state: "output-available",
      output: { open: [443] },
    });
  });

  it("starts a new assistant turn after a user boundary", () => {
    const entries = reduce([
      event("user-1", "user_message", 0, "First"),
      event("reason-1", "agent_reasoning", 1, "First activity"),
      event("tool-1", "tool_started", 2, "", {
        tool: "Port scanner",
        data: { tool_call_id: "call-1" },
      }),
      event("user-2", "user_message", 3, "Second"),
      event("reason-2", "agent_reasoning", 4, "Second activity"),
      event("tool-2", "tool_started", 5, "", {
        tool: "Port scanner",
        data: { tool_call_id: "call-2" },
      }),
      event("answer-2", "response", 6, "Second answer"),
    ]);

    expect(entries).toHaveLength(4);
    expect(entries[1]?.parts).toHaveLength(2);
    expect(entries[3]?.parts.map((part) => part.type)).toEqual([
      "reasoning",
      "tool",
      "text",
    ]);
    expect(entries[3]?.parts[1]).toMatchObject({ toolCallId: "call-2" });
  });

  it("ignores repeated event IDs after their parts have been merged", () => {
    const user = event("user-1", "user_message", 0, "Check");
    const reason = event("reason-1", "agent_reasoning", 1, "Checking");
    const tool = event("tool-1", "tool_started", 2, "", {
      tool: "Port scanner",
      data: { tool_call_id: "call-1" },
    });
    const answer = event("answer-1", "response", 3, "Done");
    const entries = reduce([user, reason, tool, answer, reason, tool, answer]);

    expect(entries).toHaveLength(2);
    expect(entries[1]?.parts.map((part) => part.type)).toEqual([
      "reasoning",
      "tool",
      "text",
    ]);
  });

  it("reconciles an optimistic user message with its server echo", () => {
    const entries = reduce([
      event("local-user-session-1-1", "user_message", 0, "Check"),
      event("server-user-1", "user_message", 1, "Check"),
      event("answer-1", "response", 2, "Done"),
    ]);

    expect(entries).toHaveLength(2);
    expect(entries[0]?.id).toBe("server-user-1");
    expect(entries[0]?.eventIds).toContain("local-user-session-1-1");
    expect(entries[0]?.eventIds).toContain("server-user-1");
  });

  it("places late history before live events without losing the live turn", () => {
    const liveAnswer = event("answer-2", "response", 6, "Latest answer");
    const history = [
      event("user-1", "user_message", 0, "Earlier"),
      event("answer-1", "response", 1, "Earlier answer"),
      event("user-2", "user_message", 4, "Latest"),
      event("reason-2", "agent_reasoning", 5, "Latest activity"),
    ];
    const entries = reconcileEvents([liveAnswer, ...history]);

    expect(entries.map((item) => item.role)).toEqual([
      "user",
      "assistant",
      "user",
      "assistant",
    ]);
    expect(entries[3]?.parts.map((part) => part.type)).toEqual([
      "reasoning",
      "text",
    ]);
  });
});
