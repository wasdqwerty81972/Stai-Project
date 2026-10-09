import { getStaiCommands } from "../stai-api";

test("loads the slash-command catalogue from the SVS-Cyber backend", async () => {
  const fetchMock = jest.fn(async () => ({
    ok: true,
    json: async () => [
      {
        name: "plan",
        description: "Create an investigation plan",
        argument_hint: "objective",
      },
    ],
  }));
  global.fetch = fetchMock as typeof fetch;

  await expect(getStaiCommands()).resolves.toEqual([
    {
      name: "plan",
      description: "Create an investigation plan",
      argument_hint: "objective",
    },
  ]);
  expect(String(fetchMock.mock.calls[0]?.[0])).toBe(
    "http://localhost:6764/api/commands",
  );
});
