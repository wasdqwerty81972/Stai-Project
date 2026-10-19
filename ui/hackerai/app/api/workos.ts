import { WorkOS } from "@workos-inc/node";

let workosClient: WorkOS | null = null;

export function getWorkOS(): WorkOS {
  if (workosClient) return workosClient;

  const apiKey = process.env.WORKOS_API_KEY ?? process.env.NEXT_PUBLIC_WORKOS_API_KEY;
  const clientId =
    process.env.WORKOS_CLIENT_ID ?? process.env.NEXT_PUBLIC_WORKOS_CLIENT_ID;

  if (!apiKey && !clientId) {
    throw new Error(
      "WorkOS must be configured with either WORKOS_API_KEY or WORKOS_CLIENT_ID (or their NEXT_PUBLIC_* equivalents)",
    );
  }

  workosClient = new WorkOS({
    ...(apiKey ? { apiKey } : {}),
    ...(clientId ? { clientId } : {}),
  });
  return workosClient;
}

export const workos = new Proxy({} as WorkOS, {
  get(_target, prop) {
    const client = getWorkOS();
    const value = Reflect.get(client, prop, client);
    return typeof value === "function" ? value.bind(client) : value;
  },
});
