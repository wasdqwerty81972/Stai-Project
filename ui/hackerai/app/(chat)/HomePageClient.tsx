"use client";

import React from "react";
import { StaiChatWorkspace } from "../components/StaiChatWorkspace";

export default function HomePageClient() {
  return <StaiChatWorkspace landing={false} sessionId="default" />;
}

