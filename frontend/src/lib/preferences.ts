// 通用设置的客户端持久化（localStorage + 同窗口事件广播）。

import { useEffect, useState } from "react";

export type ExpandMode = "inline" | "drawer";

const EXPAND_MODE_KEY = "dm.preferences.expandMode";
const EXPAND_MODE_EVENT = "dm:preference-changed:expand-mode";

const VALID_MODES: ReadonlySet<ExpandMode> = new Set(["inline", "drawer"]);

function isExpandMode(value: unknown): value is ExpandMode {
  return typeof value === "string" && VALID_MODES.has(value as ExpandMode);
}

export function readExpandMode(): ExpandMode {
  try {
    const v = window.localStorage.getItem(EXPAND_MODE_KEY);
    return isExpandMode(v) ? v : "inline";
  } catch {
    return "inline";
  }
}

export function writeExpandMode(mode: ExpandMode) {
  try {
    window.localStorage.setItem(EXPAND_MODE_KEY, mode);
  } catch {
    // ignore quota/permission errors
  }
  window.dispatchEvent(
    new CustomEvent<ExpandMode>(EXPAND_MODE_EVENT, { detail: mode })
  );
}

export function useExpandMode(): [ExpandMode, (next: ExpandMode) => void] {
  const [mode, setMode] = useState<ExpandMode>(() => readExpandMode());

  useEffect(() => {
    function onCustom(e: Event) {
      const v = (e as CustomEvent<ExpandMode>).detail;
      if (isExpandMode(v)) setMode(v);
    }
    function onStorage(e: StorageEvent) {
      if (e.key !== EXPAND_MODE_KEY) return;
      const v = e.newValue;
      setMode(isExpandMode(v) ? v : "inline");
    }
    window.addEventListener(EXPAND_MODE_EVENT, onCustom as EventListener);
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener(EXPAND_MODE_EVENT, onCustom as EventListener);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  function setAndPersist(next: ExpandMode) {
    setMode(next);
    writeExpandMode(next);
  }

  return [mode, setAndPersist];
}
