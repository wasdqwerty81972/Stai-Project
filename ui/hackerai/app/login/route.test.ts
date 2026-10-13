/** @jest-environment node */

import { getSignInUrl } from "@workos-inc/authkit-nextjs";
import { GET } from "./route";

jest.mock("@workos-inc/authkit-nextjs", () => ({
  getSignInUrl: jest.fn(),
}));

describe("GET /login", () => {
  const workosEnv = {
    WORKOS_API_KEY: process.env.WORKOS_API_KEY,
    WORKOS_CLIENT_ID: process.env.WORKOS_CLIENT_ID,
    NEXT_PUBLIC_WORKOS_API_KEY: process.env.NEXT_PUBLIC_WORKOS_API_KEY,
    NEXT_PUBLIC_WORKOS_CLIENT_ID: process.env.NEXT_PUBLIC_WORKOS_CLIENT_ID,
  };

  beforeEach(() => {
    delete process.env.WORKOS_API_KEY;
    delete process.env.WORKOS_CLIENT_ID;
    delete process.env.NEXT_PUBLIC_WORKOS_API_KEY;
    delete process.env.NEXT_PUBLIC_WORKOS_CLIENT_ID;
    jest.mocked(getSignInUrl).mockClear();
  });

  afterAll(() => {
    for (const [name, value] of Object.entries(workosEnv)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  });

  it("returns an actionable unavailable response without calling WorkOS", async () => {
    const response = await GET(new Request("http://localhost:6763/login"));

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toContain("text/plain");
    await expect(response.text()).resolves.toContain(
      "Set WORKOS_API_KEY or WORKOS_CLIENT_ID",
    );
    expect(getSignInUrl).not.toHaveBeenCalled();
  });

  it("continues to redirect to WorkOS when credentials are configured", async () => {
    process.env.WORKOS_CLIENT_ID = "client_test";
    jest
      .mocked(getSignInUrl)
      .mockResolvedValue("https://sign-in.example.test/authorize");

    const response = await GET(new Request("http://localhost:6763/login"));

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe(
      "https://sign-in.example.test/authorize",
    );
    expect(getSignInUrl).toHaveBeenCalledTimes(1);
  });
});
