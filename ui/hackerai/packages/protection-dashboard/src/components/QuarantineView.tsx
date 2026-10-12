import { useState } from "react";
import { LockKeyhole, RefreshCw } from "lucide-react";
import type { QuarantineItem } from "../protection-api";
import { EmptyState } from "./EmptyState";
import { PageHeading } from "./PageHeading";

export function QuarantineView({
  items,
  error,
  onRestore,
}: {
  items: QuarantineItem[] | null;
  error: string | null;
  onRestore: (itemId: string) => Promise<void>;
}) {
  const [restoring, setRestoring] = useState<string | null>(null);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const [restoreSuccess, setRestoreSuccess] = useState(false);
  const restore = async (itemId: string) => {
    setRestoring(itemId);
    setRestoreError(null);
    setRestoreSuccess(false);
    try {
      await onRestore(itemId);
      setRestoreSuccess(true);
    } catch (cause) {
      setRestoreError(cause instanceof Error ? cause.message : "Restore was not completed.");
    } finally {
      setRestoring(null);
    }
  };

  return (
    <>
      <PageHeading
        eyebrow="ISOLATED ITEMS"
        title="Quarantine"
        description="Items moved by verified protection outcomes. Restore always asks the service to rescan first."
      />
      {restoreError && <div role="alert" className="inline-alert error-alert">{restoreError}</div>}
      {restoreSuccess && <div role="status" className="inline-alert success-alert">Restore completed. The item was rescanned before it was returned.</div>}
      <section className="panel">
        <div className="panel-heading panel-heading-wide">
          <div>
            <div className="eyebrow">QUARANTINE STORE</div>
            <h2>Isolated files</h2>
          </div>
          {items !== null && !error && <span className="subtle-count">{items.length} items</span>}
        </div>
        {error ? (
          <div role="alert" className="inline-alert error-alert">{error}</div>
        ) : items === null ? (
          <div className="loading-row"><span className="spinner" /> Loading quarantine…</div>
        ) : items.length === 0 ? (
          <EmptyState title="Quarantine is empty" description="No verified quarantine moves have been recorded." />
        ) : (
          <div className="quarantine-list">
            {items.map((item) => (
              <article className="quarantine-row" key={item.item_id}>
                <span className="quarantine-symbol" aria-hidden="true"><LockKeyhole size={18} /></span>
                <div className="quarantine-copy">
                  <strong>{item.original_path}</strong>
                  <span>SHA-256 {item.sha256}</span>
                  <span>Rule {item.rule_id} · {item.rule_version}</span>
                </div>
                {item.restored_at || item.restore_result === "restored" ? (
                  <span className="restored-tag">Restored</span>
                ) : (
                  <button
                    className="button button-secondary restore-button"
                    disabled={restoring !== null}
                    onClick={() => void restore(item.item_id)}
                    type="button"
                  >
                    {restoring === item.item_id ? <RefreshCw size={14} className="spin" /> : null}
                    {restoring === item.item_id ? "Restoring…" : "Restore item"}
                  </button>
                )}
              </article>
            ))}
          </div>
        )}
      </section>
    </>
  );
}
