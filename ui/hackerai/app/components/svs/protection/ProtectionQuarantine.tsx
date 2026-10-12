"use client";

import { useCallback, useEffect, useState } from "react";
import { Archive, RotateCcw, Loader2 } from "lucide-react";
import {
  listQuarantine,
  restoreQuarantine,
  type QuarantineItem,
} from "@/lib/stai-protection-api";
import { AsyncState, formatTimestamp, shortHash } from "./ProtectionPrimitives";

interface RestoreOutcome {
  success: boolean;
  message: string;
}

export function ProtectionQuarantine() {
  const [items, setItems] = useState<QuarantineItem[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [restoringId, setRestoringId] = useState<string>("");
  const [outcomes, setOutcomes] = useState<Record<string, RestoreOutcome>>({});

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setItems(await listQuarantine());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Quarantine list unavailable");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function handleRestore(item: QuarantineItem) {
    setRestoringId(item.item_id);
    setOutcomes((prev) => {
      const next = { ...prev };
      delete next[item.item_id];
      return next;
    });
    // restoreQuarantine never throws — it returns a typed result either way.
    const result = await restoreQuarantine(item.item_id);
    setOutcomes((prev) => ({
      ...prev,
      [item.item_id]: {
        success: result.success,
        message: result.success
          ? result.item?.restore_result || "Restored to original path."
          : result.error || "Restore failed.",
      },
    }));
    if (result.success && result.item) {
      setItems((prev) =>
        (prev ?? []).map((existing) =>
          existing.item_id === item.item_id ? result.item! : existing,
        ),
      );
    }
    setRestoringId("");
  }

  return (
    <section
      aria-label="Quarantine"
      className="rounded-xl border border-border bg-card/40 p-5"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Archive className="size-4 text-amber-300" aria-hidden="true" />
          <h3 className="text-sm font-semibold text-foreground">Quarantine</h3>
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={loading}
          className="rounded-md border border-border bg-background px-2.5 py-1 text-xs font-medium text-foreground transition-colors hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring disabled:opacity-50"
        >
          Refresh
        </button>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">
        Restoring rescans the item and records the result. The agent cannot
        restore or delete files on its own.
      </p>

      <div className="mt-4">
        {loading && items === null ? (
          <AsyncState kind="loading" title="Loading quarantine…" />
        ) : error ? (
          <AsyncState kind="error" title="Quarantine unavailable" detail={error} />
        ) : (items?.length ?? 0) === 0 ? (
          <AsyncState
            kind="empty"
            title="Quarantine is empty"
            detail="Items appear here only after a verified move into the protected quarantine store."
          />
        ) : (
          <ul className="space-y-2">
            {items!.map((item) => {
              const outcome = outcomes[item.item_id];
              const restored = Boolean(item.restored_at);
              return (
                <li
                  key={item.item_id}
                  className="rounded-lg border border-border bg-background/40 p-3"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <p className="break-all text-sm font-medium text-foreground">
                        {item.original_path}
                      </p>
                      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                        <span>{item.rule_id} v{item.rule_version}</span>
                        <span>sha256 {shortHash(item.sha256)}</span>
                        <span>action {item.action_result}</span>
                        <span>added {formatTimestamp(item.created_at)}</span>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => void handleRestore(item)}
                      disabled={restoringId !== "" || restored}
                      className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-border px-2.5 py-1 text-xs font-medium text-foreground transition-colors hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {restoringId === item.item_id ? (
                        <Loader2 className="size-3.5 motion-safe:animate-spin" aria-hidden="true" />
                      ) : (
                        <RotateCcw className="size-3.5" aria-hidden="true" />
                      )}
                      {restored ? "Restored" : "Restore"}
                    </button>
                  </div>

                  {restored && !outcome ? (
                    <p className="mt-2 text-[11px] text-emerald-300">
                      Restored {formatTimestamp(item.restored_at)}
                      {item.restore_result ? ` · ${item.restore_result}` : ""}
                    </p>
                  ) : null}

                  {outcome ? (
                    <p
                      role={outcome.success ? "status" : "alert"}
                      className={`mt-2 rounded-md border px-3 py-2 text-[11px] ${
                        outcome.success
                          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
                          : "border-destructive/40 bg-destructive/10 text-destructive"
                      }`}
                    >
                      {outcome.success ? "Restore succeeded: " : "Restore failed: "}
                      {outcome.message}
                    </p>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}
