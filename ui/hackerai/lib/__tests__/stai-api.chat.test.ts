import { sendStaiMessage } from "../stai-api";

describe("SVS chat request settings", () => {
  it("sends the selected reasoning level with the message", async () => {
    const fetchMock = jest.fn(async () => ({
      ok: true,
      json: async () => ({
        status: "completed",
        session_id: "session-1",
        message: "Done",
      }),
    }));
    global.fetch = fetchMock as typeof fetch;

    await sendStaiMessage("Investigate", "session-1", "auto", "high");

    const [, init] = fetchMock.mock.calls[0] ?? [];
    expect(JSON.parse(String(init?.body))).toEqual({
      message: "Investigate",
      session_id: "session-1",
      model: "auto",
      reasoning_level: "high",
    });
  });
});
