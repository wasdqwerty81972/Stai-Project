"use client";

import { use } from "react";
import { StaiChatWorkspace } from "@/app/components/StaiChatWorkspace";

export default function Page(props: { params: Promise<{ id: string }> }) {
  const params = use(props.params);
  const chatId = params.id;

  return <StaiChatWorkspace sessionId={chatId} />;
}
