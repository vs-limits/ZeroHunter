/** 简单 GET 请求内存缓存，用于 Scan 内 tab 切换避免重复拉取。 */

const DEFAULT_TTL_MS = 30_000;

interface CacheEntry<T> {
  expiresAt: number;
  value: T;
}

const store = new Map<string, CacheEntry<unknown>>();

export function cacheKey(parts: (string | number | null | undefined)[]): string {
  return parts.map((p) => (p == null ? "" : String(p))).join("|");
}

export function getCached<T>(key: string): T | undefined {
  const hit = store.get(key);
  if (!hit) return undefined;
  if (Date.now() > hit.expiresAt) {
    store.delete(key);
    return undefined;
  }
  return hit.value as T;
}

export function setCached<T>(key: string, value: T, ttlMs = DEFAULT_TTL_MS): void {
  store.set(key, { value, expiresAt: Date.now() + ttlMs });
}

export async function fetchCached<T>(
  key: string,
  loader: () => Promise<T>,
  opts?: { ttlMs?: number; force?: boolean }
): Promise<T> {
  if (!opts?.force) {
    const hit = getCached<T>(key);
    if (hit !== undefined) return hit;
  }
  const value = await loader();
  setCached(key, value, opts?.ttlMs);
  return value;
}

export function invalidateCache(prefix?: string): void {
  if (!prefix) {
    store.clear();
    return;
  }
  for (const key of store.keys()) {
    if (key.startsWith(prefix)) store.delete(key);
  }
}
