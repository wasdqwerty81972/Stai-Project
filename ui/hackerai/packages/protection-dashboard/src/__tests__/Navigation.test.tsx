import { fireEvent, render, screen } from "@testing-library/react";
import { Navigation } from "../components/Navigation";

test("opens the local protection agent view", () => {
  const onNavigate = jest.fn();

  render(<Navigation page="Dashboard" onNavigate={onNavigate} />);
  fireEvent.click(screen.getByRole("button", { name: "AI Agent" }));

  expect(onNavigate).toHaveBeenCalledWith("AI Agent");
});
