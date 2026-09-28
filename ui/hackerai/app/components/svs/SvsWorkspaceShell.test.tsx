import "@testing-library/jest-dom";
import { fireEvent, render, screen } from "@testing-library/react";
import { SvsWorkspaceSidebar } from "./SvsWorkspaceSidebar";
import { SvsWorkspaceHeader } from "./SvsWorkspaceHeader";
import { SvsLandingState } from "./SvsLandingState";

const conversations = [
  {
    id: "first session",
    title: "Review authentication flow",
    last_message: "Check the login route",
    timestamp: "2026-09-27T10:00:00Z",
  },
  {
    id: "second",
    title: "Inspect request headers",
    timestamp: "2026-09-26T10:00:00Z",
  },
];

describe("SvsWorkspaceSidebar", () => {
  it("navigates to investigations and identifies the active one", () => {
    render(
      <SvsWorkspaceSidebar
        conversations={conversations}
        activeSessionId="first session"
        onClearAll={jest.fn()}
        collapsed={false}
        onCollapsedChange={jest.fn()}
      />,
    );

    expect(
      screen.getByRole("link", { name: /new investigation/i }),
    ).toHaveAttribute("href", "/");
    expect(
      screen.getByRole("link", { name: /review authentication flow/i }),
    ).toHaveAttribute("href", "/c/first%20session");
    expect(
      screen.getByRole("link", { name: /review authentication flow/i }),
    ).toHaveAttribute("aria-current", "page");
    expect(
      screen.getByRole("link", { name: /inspect request headers/i }),
    ).not.toHaveAttribute("aria-current");
  });

  it("filters history, handles an empty list, and only offers clearing when there is history", () => {
    const onClearAll = jest.fn();
    const { rerender } = render(
      <SvsWorkspaceSidebar
        conversations={conversations}
        activeSessionId=""
        onClearAll={onClearAll}
        collapsed={false}
        onCollapsedChange={jest.fn()}
      />,
    );

    fireEvent.change(
      screen.getByRole("searchbox", { name: /search investigations/i }),
      {
        target: { value: "headers" },
      },
    );
    expect(
      screen.queryByRole("link", { name: /review authentication flow/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /inspect request headers/i }),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: /clear all investigations/i }),
    );
    expect(onClearAll).toHaveBeenCalledTimes(1);

    rerender(
      <SvsWorkspaceSidebar
        conversations={[]}
        activeSessionId=""
        onClearAll={onClearAll}
        collapsed={false}
        onCollapsedChange={jest.fn()}
      />,
    );
    expect(screen.getByText(/no investigations yet/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /clear all investigations/i }),
    ).toBeDisabled();
  });

  it("exposes compact and mobile navigation controls", () => {
    const onCollapsedChange = jest.fn();
    const { rerender } = render(
      <SvsWorkspaceSidebar
        conversations={conversations}
        activeSessionId=""
        onClearAll={jest.fn()}
        collapsed
        onCollapsedChange={onCollapsedChange}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /expand navigation/i }));
    expect(onCollapsedChange).toHaveBeenCalledWith(false);
    expect(
      screen.getByRole("link", { name: /new investigation/i }),
    ).toBeInTheDocument();

    rerender(
      <SvsWorkspaceSidebar
        conversations={conversations}
        activeSessionId=""
        onClearAll={jest.fn()}
        collapsed={false}
        onCollapsedChange={onCollapsedChange}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /close navigation/i }));
    expect(onCollapsedChange).toHaveBeenCalledWith(true);
  });
});

describe("SvsWorkspaceHeader", () => {
  it.each([
    ["idle", "Local-first workspace"],
    ["connecting", "Connecting to local agent"],
    ["connected", "Agent connected"],
    ["disconnected", "Agent disconnected"],
  ] as const)("shows the %s connection state", (connection, label) => {
    render(
      <SvsWorkspaceHeader
        title="Authentication review"
        connection={connection}
        running={false}
        onOpenNavigation={jest.fn()}
      />,
    );
    expect(screen.getByRole("status")).toHaveTextContent(label);
    expect(
      screen.getByRole("heading", { name: "Authentication review" }),
    ).toBeInTheDocument();
  });

  it("keeps mobile navigation actionable while a run is active", () => {
    const onOpenNavigation = jest.fn();
    render(
      <SvsWorkspaceHeader
        title="Review"
        connection="connected"
        running
        onOpenNavigation={onOpenNavigation}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /open navigation/i }));
    expect(onOpenNavigation).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Agent running")).toBeInTheDocument();
  });
});

describe("SvsLandingState", () => {
  it("offers concrete defensive prompts through the suggestion callback", () => {
    const onSuggestion = jest.fn();
    render(<SvsLandingState onSuggestion={onSuggestion} />);
    expect(
      screen.getByRole("heading", { name: /start a security investigation/i }),
    ).toBeInTheDocument();
    const suggestion = screen.getByRole("button", {
      name: /review an authentication flow/i,
    });
    fireEvent.click(suggestion);
    expect(onSuggestion).toHaveBeenCalledWith(
      expect.stringContaining("authentication"),
    );
    expect(screen.getByText("Define the scope")).toBeInTheDocument();
    expect(screen.getByText("Review the evidence")).toBeInTheDocument();
  });
});
