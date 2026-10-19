import { getSignInUrl } from "@workos-inc/authkit-nextjs";
import { redirectToAuthorizationUrl } from "@/lib/auth/auth-redirect-intents";

export async function GET(request: Request) {
  const isWorkOSConfigured = Boolean(
    process.env.WORKOS_API_KEY ||
    process.env.WORKOS_CLIENT_ID ||
    process.env.NEXT_PUBLIC_WORKOS_API_KEY ||
    process.env.NEXT_PUBLIC_WORKOS_CLIENT_ID,
  );

  if (!isWorkOSConfigured) {
    return new Response(
      "Sign-in is unavailable because WorkOS is not configured. Set WORKOS_API_KEY or WORKOS_CLIENT_ID (or the corresponding NEXT_PUBLIC_* variable) in ui/hackerai/.env.local, then restart the app.",
      {
        status: 503,
        headers: {
          "cache-control": "no-store",
          "content-type": "text/plain; charset=utf-8",
        },
      },
    );
  }

  const url = new URL(request.url);
  const authorizationUrl = await getSignInUrl();
  return redirectToAuthorizationUrl(authorizationUrl, url);
}
