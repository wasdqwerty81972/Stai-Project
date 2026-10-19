"use client";

import React from "react";

/**
 * Shared layout for / and /c/[id] in SVS-Cyber.
 * Full-height container for the HackerAI UI workspace.
 */
export default function ChatRouteLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="h-dvh min-h-0 flex flex-col bg-background overflow-hidden">
      {children}
    </div>
  );
}
