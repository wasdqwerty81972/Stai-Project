import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { createRef } from "react";
import { SvsTranscript, type SvsTranscriptEntry } from "./SvsTranscript";

const timestamp = "2026-09-27T10:00:00.000Z";

function entry(
  id: string,
  role: SvsTranscriptEntry["role"],
  parts: SvsTranscriptEntry["parts"],
): SvsTranscriptEntry {
  return { id, role, parts, timestamp };
}

function show(
  entries: SvsTranscriptEntry[],
  options: {
    running?: boolean;
    error?: string | null;
    onApproval?: (requestId: string, approved: boolean) => void | Promise<void>;
  } = {},
) {
  return render(
    <SvsTranscript
      entries={entries}
      running={options.running ?? false}
      error={options.error ?? null}
      sessionId="session-1"
      onApproval={options.onApproval ?? jest.fn()}
      bottomRef={createRef<HTMLDivElement>()}
    />,
  );
}

describe("SvsTranscript", () => {
  it("shows user text and the assistant answer", () => {
    show([
      entry("user", "user", [{ type: "text", text: "Check this host" }]),
      entry("answer", "assistant", [
        { type: "text", text: "Found an exposed service" },
      ]),
    ]);

    expect(screen.getByText("Check this host")).toBeInTheDocument();
    expect(screen.getByText("Found an exposed service")).toBeInTheDocument();
  });

  it("shows only supplied visible activity", () => {
    show([
      entry("work", "assistant", [
        { type: "reasoning", activity: "Checking the HTTP response" },
      ]),
    ]);

    expect(screen.getByText("Checking the HTTP response")).toBeInTheDocument();
  });

  it("groups consecutive activity into one collapsible work section", () => {
    show([
      entry("work", "assistant", [
        { type: "reasoning", activity: "Resolving the host" },
        { type: "reasoning", activity: "Checking the response" },
        { type: "text", text: "The host responded." },
      ]),
    ]);

    const workTrigger = screen.getByRole("button", { name: /worked/i });
    expect(screen.getAllByRole("button", { name: /worked/i })).toHaveLength(1);
    expect(screen.queryByText("Resolving the host")).not.toBeInTheDocument();
    fireEvent.click(workTrigger);
    expect(screen.getByText("Resolving the host")).toBeInTheDocument();
    expect(screen.getByText("Checking the response")).toBeInTheDocument();
    fireEvent.click(workTrigger);
    expect(screen.queryByText("Resolving the host")).not.toBeInTheDocument();
    expect(screen.getByText("The host responded.")).toBeInTheDocument();
  });

  it("distinguishes completed and failed tools and exposes their evidence", () => {
    show([
      entry("work", "assistant", [
        {
          type: "tool",
          toolCallId: "ok",
          toolName: "HTTP probe",
          state: "output-available",
          input: { url: "https://example.test" },
          output: { status: 200 },
        },
        {
          type: "tool",
          toolCallId: "failed",
          toolName: "Port scanner",
          state: "output-error",
          errorText: "Connection refused",
        },
      ]),
    ]);

    expect(
      within(screen.getByTestId("tool-part-ok")).getByText("completed"),
    ).toBeInTheDocument();
    expect(
      within(screen.getByTestId("tool-part-failed")).getByText("failed"),
    ).toBeInTheDocument();
    expect(screen.getByText(/Connection refused/i)).toBeInTheDocument();
    expect(screen.getByText(/"status": 200/i)).toBeInTheDocument();
  });

  it("submits approval and waits for its result before confirming", async () => {
    let finish!: () => void;
    const onApproval = jest.fn(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    show(
      [
        entry("work", "assistant", [
          {
            type: "tool",
            toolCallId: "approve",
            toolName: "Shell command",
            state: "approval-requested",
            approval: { requestId: "request-1" },
          },
        ]),
      ],
      { onApproval },
    );

    fireEvent.click(screen.getByRole("button", { name: "Allow" }));
    expect(onApproval).toHaveBeenCalledWith("request-1", true);
    expect(screen.getByText(/Sending approval/i)).toBeInTheDocument();
    expect(screen.queryByText("Approved.")).not.toBeInTheDocument();
    finish();
    await waitFor(() =>
      expect(screen.getByText("Approved.")).toBeInTheDocument(),
    );
  });

  it("keeps approval available after a failed response", async () => {
    const onApproval = jest
      .fn()
      .mockRejectedValue(new Error("Backend unavailable"));
    show(
      [
        entry("work", "assistant", [
          {
            type: "tool",
            toolCallId: "approve",
            toolName: "Shell command",
            state: "approval-requested",
            approval: { requestId: "request-1" },
          },
        ]),
      ],
      { onApproval },
    );

    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Backend unavailable",
      ),
    );
    expect(screen.getByRole("button", { name: "Deny" })).toBeEnabled();
    expect(screen.queryByText("Denied.")).not.toBeInTheDocument();
  });

  it("shows an empty invitation and only a real pending state", () => {
    const { rerender } = show([]);
    expect(
      screen.getByText(/What investigation are we running/i),
    ).toBeInTheDocument();
    expect(screen.queryByText("Thinking...")).not.toBeInTheDocument();

    rerender(
      <SvsTranscript
        entries={[
          entry("user", "user", [{ type: "text", text: "Investigate" }]),
        ]}
        running
        error={null}
        sessionId="session-1"
        onApproval={jest.fn()}
        bottomRef={createRef<HTMLDivElement>()}
      />,
    );
    expect(screen.getByText("Thinking...")).toBeInTheDocument();
  });
});
