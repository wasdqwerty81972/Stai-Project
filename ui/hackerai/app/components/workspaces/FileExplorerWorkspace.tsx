"use client";

import { FileText } from "lucide-react";
import type { ToolWorkspaceContent } from "@/app/contexts/ToolWorkspaceContext";
import { checkDriveAccess, DriveBlockedNotice } from "./DriveProtectionGuard";

export function FileExplorerWorkspace({ content }: { content: ToolWorkspaceContent }) {
  const path = content.filePath || String(content.metadata?.path || "Path unavailable");
  const driveCheck = checkDriveAccess(path, "read");

  return (
    <div className="h-full overflow-auto p-4 space-y-4">
      <div className="flex items-center gap-2 text-sm font-medium">
        <FileText className="size-4" aria-hidden="true" /> File inspection
      </div>

      {driveCheck.blocked && driveCheck.reason && (
        <DriveBlockedNotice
          path={path}
          reason={driveCheck.reason}
          message={driveCheck.message}
        />
      )}

      <div className="rounded border border-border bg-muted/20 p-3 font-mono text-xs break-all">
        {path}
      </div>
      <dl className="grid grid-cols-2 gap-3 text-xs">
        <dt className="text-muted-foreground">Status</dt>
        <dd>{content.status}</dd>
        <dt className="text-muted-foreground">Type</dt>
        <dd>{String(content.metadata?.fileType || "unknown")}</dd>
        <dt className="text-muted-foreground">Size</dt>
        <dd>{String(content.metadata?.size || "unknown")}</dd>
      </dl>
    </div>
  );
}

