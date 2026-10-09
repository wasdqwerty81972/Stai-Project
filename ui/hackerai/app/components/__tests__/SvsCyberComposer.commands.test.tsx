import { fireEvent, render, screen } from "@testing-library/react";
import { SvsCyberComposer } from "../SvsCyberComposer";

const commands = [
  {
    name: "plan",
    description: "Create an investigation plan",
    argument_hint: "objective",
  },
  {
    name: "security",
    description: "Run a security review",
  },
];

describe("SvsCyberComposer command menu", () => {
  it("filters slash commands and inserts the selected command", () => {
    const onChange = jest.fn();
    render(
      <SvsCyberComposer
        value="/pla"
        onChange={onChange}
        onSubmit={jest.fn()}
        onStop={jest.fn()}
        status="ready"
        onModelChange={jest.fn()}
        commands={commands}
      />,
    );

    expect(screen.getByRole("listbox", { name: "Commands" })).toBeVisible();
    fireEvent.click(screen.getByRole("option", { name: /plan/i }));
    expect(onChange).toHaveBeenCalledWith("/plan ");
  });

  it("ranks a direct command-name match above description-only matches", () => {
    render(
      <SvsCyberComposer
        value="/plan"
        onChange={jest.fn()}
        onSubmit={jest.fn()}
        onStop={jest.fn()}
        status="ready"
        commands={[
          { name: "marketing-campaign", description: "Plan a campaign" },
          ...commands,
        ]}
      />,
    );

    expect(screen.getAllByRole("option")[0]).toHaveAccessibleName(
      /\/plan/i,
    );
  });

  it("supports keyboard selection and escape dismissal", () => {
    const onChange = jest.fn();
    render(
      <SvsCyberComposer
        value="/"
        onChange={onChange}
        onSubmit={jest.fn()}
        onStop={jest.fn()}
        status="ready"
        commands={commands}
      />,
    );

    const input = screen.getByTestId("chat-input");
    fireEvent.keyDown(input, { key: "ArrowDown" });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith("/security ");
    fireEvent.keyDown(input, { key: "Escape" });
    expect(screen.queryByRole("listbox", { name: "Commands" })).not.toBeInTheDocument();
  });

  it("keeps the attachment and model controls in the composer toolbar", () => {
    render(
      <SvsCyberComposer
        value=""
        onChange={jest.fn()}
        onSubmit={jest.fn()}
        onStop={jest.fn()}
        status="ready"
        onModelChange={jest.fn()}
      />,
    );

    expect(screen.getByTestId("chat-input")).toBeVisible();
    expect(screen.getByTestId("attachment-button")).toBeVisible();
    expect(screen.getByLabelText(/model:/i)).toBeVisible();
  });

  it("shows Gemini-only model choices", () => {
    const onModelChange = jest.fn();
    render(
      <SvsCyberComposer
        value=""
        onChange={jest.fn()}
        onSubmit={jest.fn()}
        onStop={jest.fn()}
        status="ready"
        onModelChange={onModelChange}
      />,
    );

    // The trigger is a Radix DropdownMenu, which opens on keydown/pointerdown.
    // A synthetic click never reaches it, so the menu stayed closed and the
    // options were never in the DOM.
    fireEvent.keyDown(screen.getByTestId("model-selector"), { key: "ArrowDown" });
    fireEvent.click(screen.getByTestId("model-option-gemini-3.1-pro-preview"));
    expect(onModelChange).toHaveBeenCalledWith("gemini-3.1-pro-preview");
  });
});
