import { NextRequest, NextResponse } from "next/server";

export const maxDuration = 420;

// Forward chat requests to the local Python backend (SVS-Cyber CyberAgent).
// The backend returns { status, message, session_id, ... } JSON.
// We convert that to an AI SDK v4 data-stream so the useChat hook can consume it.

const BACKEND_ORIGIN =
  process.env.NEXT_PUBLIC_BACKEND_ORIGIN || "http://127.0.0.1:6764";

function extractUserText(messages: any[]): string {
  if (!Array.isArray(messages) || messages.length === 0) return "";
  // Walk backwards to find the last user message
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg.role !== "user") continue;
    // AI SDK v4 message format: parts array
    if (Array.isArray(msg.parts)) {
      const textPart = msg.parts.find((p: any) => p.type === "text");
      if (textPart?.text) return textPart.text;
    }
    // Fallback: plain content string
    if (typeof msg.content === "string") return msg.content;
  }
  return "";
}

function escapeForDataStream(text: string): string {
  // Escape backslashes, double-quotes, and newlines for the AI SDK stream format
  return text
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r");
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  try {
    const body = await req.json();

    const prompt = extractUserText(body.messages) || body.message || "";
    const sessionId = body.chatId || "default";
    const model = body.selectedModel || body.model || "auto";

    const backendRes = await fetch(`${BACKEND_ORIGIN}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: prompt,
        messages: body.messages,
        session_id: sessionId,
        model,
      }),
    });

    if (!backendRes.ok) {
      const errText = await backendRes.text();
      console.error("[/api/chat proxy] Backend error:", backendRes.status, errText);
      return NextResponse.json(
        { error: `Backend returned ${backendRes.status}: ${errText}` },
        { status: backendRes.status },
      );
    }

    const data = await backendRes.json();
    const responseText: string = data.message || data.response || data.result || "";

    // Build an AI SDK v4 data stream:
    //   0:"<escaped text chunk>"\n   — text delta
    //   d:{...}\n                    — finish marker
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        // Split into chunks so the UI renders progressively
        const chunkSize = 80;
        for (let i = 0; i < responseText.length; i += chunkSize) {
          const chunk = responseText.slice(i, i + chunkSize);
          controller.enqueue(
            encoder.encode(`0:"${escapeForDataStream(chunk)}"\n`),
          );
        }
        // Finish marker
        controller.enqueue(
          encoder.encode(
            `d:{"finishReason":"stop","usage":{"promptTokens":0,"completionTokens":0}}\n`,
          ),
        );
        controller.close();
      },
    });

    return new NextResponse(stream, {
      status: 200,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "X-Vercel-AI-Data-Stream": "v1",
        "Cache-Control": "no-cache",
      },
    });
  } catch (error) {
    console.error("[/api/chat proxy] Unexpected error:", error);
    return NextResponse.json({ error: String(error) }, { status: 500 });
  }
}
