import { authkit } from "@workos-inc/authkit-nextjs";
import { createFirstTouchAttribution } from "@/lib/analytics/acquisition";
import {
  FIRST_TOUCH_ATTRIBUTION_COOKIE_NAME,
  FIRST_TOUCH_ATTRIBUTION_MAX_AGE_SECONDS,
} from "@/lib/analytics/acquisition";
import {
  parseFirstTouchAttributionCookie,
  serializeSignedFirstTouchAttribution,
} from "@/lib/analytics/acquisition-cookie";
import { NextResponse, type NextRequest } from "next/server";

const AUTHKIT_RESPONSE_HEADERS = [
  "cache-control",
  "link",
  "proxy-authenticate",
  "set-cookie",
  "vary",
  "www-authenticate",
] as const;
const OPTIONAL_ATTRIBUTION_COOKIE_NAMES = [
  "hackerai_ref",
  "hackerai_ref_at",
] as const;
const EU_COUNTRIES = new Set([
  "AT",
  "BE",
  "BG",
  "HR",
  "CY",
  "CZ",
  "DK",
  "EE",
  "FI",
  "FR",
  "DE",
  "GR",
  "HU",
  "IE",
  "IT",
  "LV",
  "LT",
  "LU",
  "MT",
  "NL",
  "PL",
  "PT",
  "RO",
  "SK",
  "SI",
  "ES",
  "SE",
]);
const PUBLIC_PATHS = new Set([
  "/",
  "/index",
  "/product",
  "/pricing",
  "/download",
  "/trust",
  "/signup",
  "/login",
  "/robots.txt",
  "/sitemap.xml",
]);

type AuthkitResult = Awaited<ReturnType<typeof authkit>>;
type RefreshError = { error?: unknown };

function isApiRequest(request: NextRequest): boolean {
  return (
    request.nextUrl.pathname === "/api" ||
    request.nextUrl.pathname.startsWith("/api/") ||
    request.nextUrl.pathname === "/trpc" ||
    request.nextUrl.pathname.startsWith("/trpc/") ||
    request.headers.get("accept")?.includes("application/json") === true
  );
}

function isPublicRequest(request: NextRequest): boolean {
  const { pathname } = request.nextUrl;
  return (
    PUBLIC_PATHS.has(pathname) ||
    pathname.startsWith("/share/") ||
    pathname.startsWith("/invite/")
  );
}

function isServerAction(request: NextRequest): boolean {
  return (
    request.headers.has("next-action") ||
    request.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("multipart/form-data") === true
  );
}

function responseHeaders(
  authkitHeaders?: Headers,
  dropSessionHeaders = false,
): Headers {
  const result = new Headers();
  if (!authkitHeaders) return result;
  for (const [name, value] of authkitHeaders) {
    const lowerName = name.toLowerCase();
    if (
      AUTHKIT_RESPONSE_HEADERS.includes(
        lowerName as (typeof AUTHKIT_RESPONSE_HEADERS)[number],
      )
    ) {
      if (
        lowerName === "set-cookie" &&
        dropSessionHeaders &&
        /^(?:wos-session|wos-auth-verifier-state)=/i.test(value)
      ) {
        continue;
      }
      result.append(name, value);
    }
  }
  if (result.has("set-cookie") && !result.has("cache-control")) {
    result.set("cache-control", "no-store");
  }
  return result;
}

function continueRequest(
  request: NextRequest,
  auth?: AuthkitResult,
  dropSessionHeaders = false,
) {
  const headers = new Headers(request.headers);
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith("x-workos-")) headers.delete(name);
  }
  if (auth?.headers) {
    for (const [name, value] of auth.headers) {
      if (
        name.toLowerCase().startsWith("x-workos-") &&
        name.toLowerCase() !== "x-workos-session"
      )
        continue;
      if (
        [
          "x-workos-middleware",
          "x-url",
          "x-redirect-uri",
          "x-sign-up-paths",
          "x-workos-session",
        ].includes(name.toLowerCase())
      ) {
        headers.set(name, value);
      }
    }
  }
  const safeHeaders = responseHeaders(auth?.headers, dropSessionHeaders);
  return NextResponse.next({ request: { headers }, headers: safeHeaders });
}

function unauthorized(request: NextRequest, headers?: Headers) {
  if (isApiRequest(request)) {
    return NextResponse.json(
      {
        code: "unauthorized:auth",
        message: "You need to sign in before continuing.",
        cause: "Session expired or invalid",
      },
      { status: 401, ...(headers ? { headers } : {}) },
    );
  }
  const loginUrl = new URL("/login", request.url);
  const redirect = NextResponse.redirect(loginUrl);
  if (headers) {
    for (const [name, value] of headers) redirect.headers?.append(name, value);
  }
  return redirect;
}

function isEndedSessionError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const candidate = error as {
    name?: string;
    cause?: {
      error?: string;
      errorDescription?: string;
      error_description?: string;
    };
  };
  const cause = candidate.cause;
  return (
    candidate.name === "TokenRefreshError" &&
    cause?.error === "invalid_grant" &&
    /session has already ended/i.test(
      cause.errorDescription ?? cause.error_description ?? "",
    )
  );
}

function isBot(request: NextRequest): boolean {
  return /bot|crawler|spider|slurp|headless|preview/i.test(
    request.headers.get("user-agent") ?? "",
  );
}

function hasAttributionInput(request: NextRequest): boolean {
  const { searchParams } = request.nextUrl;
  return (
    [
      "utm_source",
      "utm_medium",
      "utm_campaign",
      "ref",
      "referral_code",
      "gclid",
      "msclkid",
    ].some((key) => searchParams.has(key)) ||
    Boolean(request.headers.get("referer"))
  );
}

function captureAttribution(
  request: NextRequest,
  response: ReturnType<typeof NextResponse.next>,
): void {
  const { pathname } = request.nextUrl;
  const isHtmlNavigation =
    request.headers.get("accept")?.includes("text/html") === true;
  if (!isHtmlNavigation || isBot(request) || !isPublicRequest(request)) return;

  const consent = request.cookies.get("hackerai_analytics_consent")?.value;
  const country = request.headers.get("x-vercel-ip-country")?.toUpperCase();
  const requiresConsent = country ? EU_COUNTRIES.has(country) : false;
  const isDeclined = consent === "declined";
  const hasConsent = consent === "accepted";
  if ((requiresConsent && !hasConsent) || isDeclined) {
    response.cookies.delete(FIRST_TOUCH_ATTRIBUTION_COOKIE_NAME);
    for (const name of OPTIONAL_ATTRIBUTION_COOKIE_NAMES)
      response.cookies.delete(name);
    return;
  }

  const existing = parseFirstTouchAttributionCookie(
    request.cookies.get(FIRST_TOUCH_ATTRIBUTION_COOKIE_NAME)?.value,
  );
  if (!existing && hasAttributionInput(request)) {
    const attribution = createFirstTouchAttribution({
      url: request.nextUrl,
      referer: request.headers.get("referer"),
    });
    const value = serializeSignedFirstTouchAttribution(attribution);
    if (value) {
      response.cookies.set(FIRST_TOUCH_ATTRIBUTION_COOKIE_NAME, value, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: FIRST_TOUCH_ATTRIBUTION_MAX_AGE_SECONDS,
        path: "/",
      });
    }
  }

  if ((!requiresConsent || hasConsent) && !isDeclined) {
    const referralCode =
      request.nextUrl.searchParams.get("referral_code") ??
      request.nextUrl.searchParams.get("ref");
    if (referralCode && /^[A-Za-z0-9_-]{1,80}$/.test(referralCode)) {
      response.cookies.set("hackerai_ref", referralCode, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: FIRST_TOUCH_ATTRIBUTION_MAX_AGE_SECONDS,
        path: "/",
      });
      response.cookies.set("hackerai_ref_at", String(Date.now()), {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: FIRST_TOUCH_ATTRIBUTION_MAX_AGE_SECONDS,
        path: "/",
      });
    }
  }
}

function validateServerActionOrigin(request: NextRequest): boolean {
  if (request.method.toUpperCase() !== "POST" || !isServerAction(request))
    return true;
  const origin = request.headers.get("origin");
  if (!origin || origin === "null") return true;
  try {
    const parsed = new URL(origin);
    return (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      parsed.origin === origin &&
      !origin.includes(",")
    );
  } catch {
    return false;
  }
}

function logMalformedAction(request: NextRequest): void {
  const requestId = request.headers.get("x-vercel-id")?.slice(0, 128);
  console.warn(
    JSON.stringify({
      level: "warn",
      event: "server_action_request_rejected",
      ...(requestId ? { request_id: requestId } : {}),
      pathname: request.nextUrl.pathname,
      reason: "malformed_origin",
    }),
  );
}

export default async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const isWorkOSConfigured = Boolean(
    process.env.WORKOS_API_KEY ||
      process.env.WORKOS_CLIENT_ID ||
      process.env.NEXT_PUBLIC_WORKOS_API_KEY ||
      process.env.NEXT_PUBLIC_WORKOS_CLIENT_ID,
  );
  if (
    pathname === "/api/analytics-consent" ||
    pathname === "/api/health/connectivity" ||
    pathname === "/api/health/core" ||
    pathname === "/api/health/trigger-agent-mode" ||
    pathname === "/api/cron/platform-costs/convex" ||
    pathname === "/api/cron/platform-costs/vercel" ||
    pathname === "/api/cron/subscription-pauses" ||
    pathname === "/api/internal/user-research" ||
    pathname === "/robots.txt" ||
    pathname === "/sitemap.xml"
  ) {
    return NextResponse.next();
  }

  if (!isWorkOSConfigured) {
    if (isPublicRequest(request) && !isServerAction(request)) {
      const response = NextResponse.next();
      captureAttribution(request, response);
      return response;
    }
    return unauthorized(request);
  }

  // Public pages should remain usable in a fresh local checkout before an
  // operator configures AuthKit. Protected routes still fail closed below.
  if (
    process.env.NODE_ENV === "development" &&
    isPublicRequest(request) &&
    !isServerAction(request)
  ) {
    const response = NextResponse.next();
    captureAttribution(request, response);
    return response;
  }

  const method = request.method.toUpperCase();
  if (
    (pathname === "/" || pathname === "/index") &&
    method !== "GET" &&
    method !== "HEAD" &&
    !(method === "POST" && isServerAction(request))
  ) {
    const allowed = pathname === "/" ? "GET, HEAD, POST" : "GET, HEAD";
    return NextResponse.json(
      {
        code: "method_not_allowed",
        message: `${method} is not supported for this route.`,
      },
      { status: 405, headers: { Allow: allowed } },
    );
  }

  if (!validateServerActionOrigin(request)) {
    logMalformedAction(request);
    return NextResponse.json(
      {
        code: "bad_request:request",
        message: "The request origin is invalid.",
      },
      { status: 400 },
    );
  }

  if (process.env.NODE_ENV === "development" && !isWorkOSConfigured) {
    return unauthorized(request);
  }

  let endedSession = false;
  let rateLimited = false;
  let auth: AuthkitResult | undefined;
  try {
    auth = await authkit(request, {
      onSessionRefreshError: ({ error }: RefreshError) => {
        if (isEndedSessionError(error)) {
          endedSession = true;
          console.info(
            JSON.stringify({
              level: "info",
              event: "auth.session_refresh_ended",
              service: "hackerai-web",
              pathname,
            }),
          );
        } else if (
          error &&
          typeof error === "object" &&
          "status" in error &&
          error.status === 429
        ) {
          rateLimited = true;
          console.warn(
            JSON.stringify({
              level: "warn",
              event: "auth.session_refresh_rate_limited",
              service: "hackerai-web",
              pathname,
            }),
          );
        }
      },
    } as Parameters<typeof authkit>[1]);
  } catch (error) {
    if (!isEndedSessionError(error)) throw error;
    endedSession = true;
    auth = { session: { user: null } } as AuthkitResult;
  }

  if (rateLimited) {
    if (isApiRequest(request)) {
      const headers = responseHeaders(auth?.headers, true);
      headers.set("retry-after", "5");
      return NextResponse.json(
        { code: "rate_limited", message: "Please retry shortly." },
        { status: 503, headers },
      );
    }
    const response = continueRequest(request, auth, true);
    if (endedSession) response.cookies.delete("wos-session");
    return response;
  }

  if (
    !auth?.session?.user &&
    (!isPublicRequest(request) || isServerAction(request))
  ) {
    const response = unauthorized(
      request,
      auth?.headers ? responseHeaders(auth.headers) : undefined,
    );
    if (endedSession) response.cookies.delete("wos-session");
    return response;
  }

  const response = continueRequest(request, auth, endedSession);
  if (endedSession) response.cookies.delete("wos-session");
  if (auth?.session?.user || isPublicRequest(request))
    captureAttribution(request, response);
  return response;
}

export const config = {
  matcher: [
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    "/(api|trpc)(.*)",
  ],
};
