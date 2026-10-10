/** Per-browser conveniences (recent URLs, settings). Storage can be blocked, so every access is guarded. */

const HISTORY_KEY = 'iframe-tester:history';
const SETTINGS_KEY = 'iframe-tester:settings';
const MAX_HISTORY = 8;

export interface HistoryEntry {
  url: string;
  status: 'embeddable' | 'blocked' | 'unknown';
  at: number;
}

export interface Settings {
  server: boolean;
  timeoutMs: number;
  embedder: string;
}

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function write(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* private mode or storage disabled — fine */
  }
}

export function getHistory(): HistoryEntry[] {
  const list = read<HistoryEntry[]>(HISTORY_KEY, []);
  return Array.isArray(list) ? list.filter((e) => typeof e?.url === 'string').slice(0, MAX_HISTORY) : [];
}

export function addHistory(entry: HistoryEntry): HistoryEntry[] {
  const list = [entry, ...getHistory().filter((e) => e.url !== entry.url)].slice(0, MAX_HISTORY);
  write(HISTORY_KEY, list);
  return list;
}

export function clearHistory(): void {
  try {
    localStorage.removeItem(HISTORY_KEY);
  } catch {
    /* ignore */
  }
}

export const getSettings = (): Partial<Settings> => read<Partial<Settings>>(SETTINGS_KEY, {});
export const saveSettings = (settings: Settings) => write(SETTINGS_KEY, settings);
