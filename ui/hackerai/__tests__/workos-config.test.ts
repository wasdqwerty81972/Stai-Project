describe("WorkOS configuration", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
    delete process.env.WORKOS_API_KEY;
    delete process.env.WORKOS_CLIENT_ID;
    delete process.env.NEXT_PUBLIC_WORKOS_API_KEY;
    delete process.env.NEXT_PUBLIC_WORKOS_CLIENT_ID;
  });

  afterAll(() => {
    process.env = { ...originalEnv };
  });

  it("accepts an API key without a client ID", async () => {
    process.env.WORKOS_API_KEY = "sk_test_123";

    const { getWorkOS } = await import("../app/api/workos");

    expect(() => getWorkOS()).not.toThrow();
    expect(getWorkOS()).toBeDefined();
  });

  it("accepts a public client ID without an API key", async () => {
    process.env.NEXT_PUBLIC_WORKOS_CLIENT_ID = "client_123";

    const { getWorkOS } = await import("../app/api/workos");

    expect(() => getWorkOS()).not.toThrow();
    expect(getWorkOS()).toBeDefined();
  });

  it("throws when no WorkOS credentials are configured", async () => {
    const { getWorkOS } = await import("../app/api/workos");

    expect(() => getWorkOS()).toThrow(
      /either WORKOS_API_KEY or WORKOS_CLIENT_ID/i,
    );
  });
});
