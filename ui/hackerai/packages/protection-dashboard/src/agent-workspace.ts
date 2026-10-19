import { isTauri } from "@tauri-apps/api/core";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";

const AGENT_WINDOW_LABEL = "svs-agent";
const AGENT_WORKSPACE_URL = "/?view=agent";

let openingAgentWorkspace: Promise<void> | null = null;

async function openNativeAgentWorkspace(): Promise<void> {
  const existing = await WebviewWindow.getByLabel(AGENT_WINDOW_LABEL);
  if (existing) {
    await existing.show();
    await existing.setFocus();
    return;
  }

  const agentWindow = new WebviewWindow(AGENT_WINDOW_LABEL, {
    url: AGENT_WORKSPACE_URL,
    title: "SVS Cyber AI Agent",
    width: 1180,
    height: 820,
    minWidth: 900,
    minHeight: 640,
    center: true,
    focus: true,
    resizable: true,
  });

  await new Promise<void>((resolve, reject) => {
    void agentWindow.once("tauri://created", () => resolve()).catch(reject);
    void agentWindow.once("tauri://error", () => reject(new Error("SVS Cyber could not create the AI Agent window."))).catch(reject);
  });
}

export function openAgentWorkspace(): Promise<void> {
  if (!isTauri()) {
    // Keep browser mode useful for development and non-Windows platforms.
    window.open(new URL(AGENT_WORKSPACE_URL, window.location.href).toString(), "_blank", "noopener,noreferrer");
    return Promise.resolve();
  }

  if (openingAgentWorkspace) return openingAgentWorkspace;
  openingAgentWorkspace = openNativeAgentWorkspace().finally(() => {
    openingAgentWorkspace = null;
  });
  return openingAgentWorkspace;
}
