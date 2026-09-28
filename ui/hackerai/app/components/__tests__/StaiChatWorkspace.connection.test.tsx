import { render, screen } from "@testing-library/react";
import { StaiChatWorkspace } from "../StaiChatWorkspace";
import { openStaiEvents } from "@/lib/stai-api";

jest.mock("@/lib/stai-api", () => ({
  openStaiEvents: jest.fn(() => ({ close: jest.fn() })),
  getStaiConversations: jest.fn(async () => []),
  getStaiMessages: jest.fn(async () => []),
  clearStaiConversations: jest.fn(async () => ({ status: "cleared", count: 0 })),
  sendStaiMessage: jest.fn(),
  cancelStaiRun: jest.fn(),
  respondToStaiApproval: jest.fn(),
}));
jest.mock("@/app/contexts/StaiGlobalState", () => ({
  StaiGlobalStateProvider: ({ children }: { children: React.ReactNode }) => children,
}));
jest.mock("@/app/contexts/ToolWorkspaceContext", () => ({
  ToolWorkspaceProvider: ({ children }: { children: React.ReactNode }) => children,
  useToolWorkspace: () => ({ openWorkspace: jest.fn(), updateWorkspaceContent: jest.fn() }),
}));
jest.mock("../ToolWorkspaceContainer", () => ({ ToolWorkspaceContainer: () => null }));
jest.mock("../SvsCyberComposer", () => ({ SvsCyberComposer: () => null }));

test("subscribes to connection state through the event stream handle callbacks", async () => {
  HTMLElement.prototype.scrollIntoView = jest.fn();
  render(<StaiChatWorkspace sessionId="alpha" />);
  expect(screen.getByText("Connecting...")).toBeInTheDocument();
  expect(screen.getByRole("navigation", { name: "Investigation history" })).toBeInTheDocument();
  expect(screen.getByLabelText("Investigation transcript")).toBeInTheDocument();
  expect(openStaiEvents).toHaveBeenCalledWith(
    expect.any(Function),
    expect.any(Function),
    expect.any(Function),
    expect.any(Function),
  );
});
