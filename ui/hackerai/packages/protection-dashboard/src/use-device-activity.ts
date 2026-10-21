import { useEffect, useState } from "react";
import { getDeviceActivity, type DeviceActivity } from "./protection-api";

export interface DeviceActivityState {
  snapshot: DeviceActivity | null;
  error: string | null;
}

/** Start inventory loading with the dashboard and retain it across tab changes. */
export function useDeviceActivity(enabled = true): DeviceActivityState {
  const [snapshot, setSnapshot] = useState<DeviceActivity | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    let timer: number | undefined;
    const poll = async () => {
      let delay = 10000;
      try {
        const current = await getDeviceActivity();
        if (stopped) return;
        setSnapshot(current);
        setError(null);
        if (current.collecting) delay = 1000;
      } catch (cause) {
        if (!stopped) setError(cause instanceof Error ? cause.message : "Live device activity is unavailable.");
      } finally {
        if (!stopped) timer = window.setTimeout(() => void poll(), delay);
      }
    };
    void poll();
    return () => {
      stopped = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [enabled]);
  return { snapshot, error };
}
