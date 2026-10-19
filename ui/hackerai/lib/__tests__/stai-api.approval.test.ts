import { respondToStaiApproval } from "../stai-api";

test("approval responses identify the active investigation session", async () => {
  const fetchMock = jest.fn(async () => ({
    ok: true,
    json: async () => ({ request_id: "request-1", approved: true }),
  }));
  global.fetch = fetchMock as typeof fetch;

  await respondToStaiApproval("request-1", true, "session-alpha");

  const requestedUrl = fetchMock.mock.calls[0]?.[0];
  expect(String(requestedUrl)).toContain("session_id=session-alpha");
  expect(String(requestedUrl)).toContain("approved=true");
});
