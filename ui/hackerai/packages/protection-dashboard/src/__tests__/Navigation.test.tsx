import { fireEvent, render, screen } from "@testing-library/react";
import { Navigation } from "../components/Navigation";

test("opens the HackerAI agent workspace without navigating the protection dashboard", () => {
  const onNavigate = jest.fn();
  const onOpenAgent = jest.fn();

  render(<Navigation page="Dashboard" onNavigate={onNavigate} onOpenAgent={onOpenAgent} />);
  fireEvent.click(screen.getByRole("button", { name: "AI Agent" }));

  expect(onOpenAgent).toHaveBeenCalledTimes(1);
  expect(onNavigate).not.toHaveBeenCalled();
});
