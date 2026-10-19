"use client";

import Link from "next/link";
import { useState } from "react";
import {
  History,
  PanelLeft,
  PanelLeftClose,
  Search,
  Shield,
  SquarePen,
  Trash2,
  X,
} from "lucide-react";

interface ConversationSummary {
  id: string;
  title: string;
  last_message?: string;
  timestamp: string;
}

interface SvsWorkspaceSidebarProps {
  conversations: ConversationSummary[];
  activeSessionId?: string;
  onClearAll: () => void | Promise<void>;
  collapsed: boolean;
  onCollapsedChange: (value: boolean) => void;
}

export function SvsWorkspaceSidebar({
  conversations,
  activeSessionId,
  onClearAll,
  collapsed,
  onCollapsedChange,
}: SvsWorkspaceSidebarProps) {
  const [query, setQuery] = useState("");
  const filtered = conversations.filter((conversation) =>
    conversation.title
      .toLocaleLowerCase()
      .includes(query.trim().toLocaleLowerCase()),
  );

  return (
    <>
      {!collapsed && (
        <button
          type="button"
          aria-label="Dismiss navigation overlay"
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-[2px] md:hidden"
          onClick={() => onCollapsedChange(true)}
        />
      )}
      <aside
        aria-label="Investigation navigation"
        className={`fixed inset-y-0 left-0 z-50 flex h-full max-h-dvh w-[min(19rem,calc(100vw-2.5rem))] shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground shadow-2xl transition-[width,transform] duration-200 ease-out motion-reduce:transition-none md:relative md:z-auto md:max-h-none md:shadow-none ${
          collapsed
            ? "-translate-x-full max-md:invisible md:w-14 md:translate-x-0"
            : "translate-x-0 md:w-[280px]"
        }`}
      >
        <div
          className={`flex h-16 shrink-0 items-center ${collapsed ? "justify-center px-2" : "justify-between px-4"}`}
        >
          {!collapsed && (
            <Link
              href="/"
              className="flex min-w-0 items-center gap-2.5 rounded-lg text-sm font-semibold tracking-tight focus-visible:outline-2 focus-visible:outline-ring"
            >
              <span className="flex size-8 shrink-0 items-center justify-center rounded-xl border border-sidebar-border bg-sidebar-accent">
                <Shield className="size-4" aria-hidden="true" />
              </span>
              <span>SVS-Cyber</span>
            </Link>
          )}
          <button
            type="button"
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            title={collapsed ? "Expand navigation" : "Collapse navigation"}
            onClick={() => onCollapsedChange(!collapsed)}
            className={`hidden size-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-foreground focus-visible:outline-2 focus-visible:outline-ring md:flex ${collapsed ? "mt-2" : ""}`}
          >
            {collapsed ? (
              <PanelLeft className="size-4" />
            ) : (
              <PanelLeftClose className="size-4" />
            )}
          </button>
          {!collapsed && (
            <button
              type="button"
              aria-label="Close navigation"
              onClick={() => onCollapsedChange(true)}
              className="flex size-9 items-center justify-center rounded-lg text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-foreground focus-visible:outline-2 focus-visible:outline-ring md:hidden"
            >
              <X className="size-5" />
            </button>
          )}
        </div>

        {collapsed ? (
          <div className="hidden flex-col items-center gap-2 px-2 md:flex">
            <Link
              href="/"
              aria-label="New investigation"
              title="New investigation"
              className="flex size-9 items-center justify-center rounded-lg text-sidebar-foreground hover:bg-sidebar-accent focus-visible:outline-2 focus-visible:outline-ring"
            >
              <SquarePen className="size-4" />
            </Link>
          </div>
        ) : (
          <>
            <div className="shrink-0 space-y-3 px-3 pb-4">
              <Link
                href="/"
                className="flex min-h-10 items-center gap-2.5 rounded-xl border border-sidebar-border bg-sidebar-accent/50 px-3 text-sm font-medium transition-colors hover:bg-sidebar-accent focus-visible:outline-2 focus-visible:outline-ring"
              >
                <SquarePen className="size-4 shrink-0" aria-hidden="true" />
                New investigation
              </Link>
              <label className="flex h-9 items-center gap-2 rounded-lg border border-sidebar-border bg-sidebar-accent/30 px-3 text-muted-foreground focus-within:border-ring">
                <Search className="size-4 shrink-0" aria-hidden="true" />
                <span className="sr-only">Search investigations</span>
                <input
                  type="search"
                  aria-label="Search investigations"
                  placeholder="Search investigations"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  className="min-w-0 flex-1 bg-transparent text-sm text-sidebar-foreground outline-none placeholder:text-muted-foreground"
                />
              </label>
            </div>

            <nav
              aria-label="Investigation history"
              className="min-h-0 flex-1 overflow-y-auto px-2 pb-3 sidebar-chat-scroll"
            >
              <div className="flex items-center justify-between px-2 pb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
                <span>Investigations</span>
                <span>{conversations.length}</span>
              </div>
              {conversations.length === 0 ? (
                <div className="mx-1 rounded-xl border border-dashed border-sidebar-border px-3 py-5 text-center text-xs leading-relaxed text-muted-foreground">
                  <History className="mx-auto mb-2 size-4" aria-hidden="true" />
                  No investigations yet
                </div>
              ) : filtered.length === 0 ? (
                <p className="px-3 py-4 text-xs text-muted-foreground">
                  No matching investigations
                </p>
              ) : (
                <div className="space-y-0.5">
                  {filtered.map((conversation) => (
                    <Link
                      key={conversation.id}
                      href={`/c/${encodeURIComponent(conversation.id)}`}
                      aria-current={
                        conversation.id === activeSessionId ? "page" : undefined
                      }
                      className={`group block min-w-0 rounded-xl px-3 py-2.5 transition-colors focus-visible:outline-2 focus-visible:outline-ring ${
                        conversation.id === activeSessionId
                          ? "bg-sidebar-accent text-sidebar-foreground"
                          : "text-sidebar-foreground/75 hover:bg-sidebar-accent/70 hover:text-sidebar-foreground"
                      }`}
                    >
                      <span className="block truncate text-sm font-medium">
                        {conversation.title || "Untitled investigation"}
                      </span>
                      {conversation.last_message && (
                        <span className="mt-0.5 block truncate text-xs text-muted-foreground">
                          {conversation.last_message}
                        </span>
                      )}
                    </Link>
                  ))}
                </div>
              )}
            </nav>

            <div className="shrink-0 border-t border-sidebar-border px-3 py-3">
              <button
                type="button"
                aria-label="Clear all investigations"
                disabled={conversations.length === 0}
                onClick={() => void onClearAll()}
                className="flex min-h-9 w-full items-center gap-2 rounded-lg px-2 text-xs text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-foreground disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline-2 focus-visible:outline-ring"
              >
                <Trash2 className="size-3.5" aria-hidden="true" />
                Clear all investigations
              </button>
              <p className="px-2 pt-2 text-[11px] text-muted-foreground">
                Defensive security workspace
              </p>
            </div>
          </>
        )}
      </aside>
    </>
  );
}
