/**
 * Turns whatever the user typed or pasted into a testable http(s) URL, or explains why not.
 * Pure — shared by the browser UI, the header-check API and the tests.
 */

export type ValidationResult =
  | { ok: true; url: string; /** Set when we changed the input, e.g. added https:// */ note?: string }
  | { ok: false; error: string };

export const MAX_URL_LENGTH = 2048;

/** Schemes that can run code or read local data. Never loaded, never fetched. */
const DANGEROUS = ['javascript', 'data', 'file', 'vbscript', 'blob', 'filesystem'];

const SCHEME_RE = /^([a-z][a-z0-9+.-]*):/i;

export function normalizeUrlInput(raw: string): ValidationResult {
  // Pasted links often arrive wrapped: <https://…>, "https://…", or with a trailing full stop.
  let input = raw
    .trim()
    .replace(/^[<"'`\s]+|[>"'`\s.,;]+$/g, '');

  if (!input) return { ok: false, error: 'Enter a website address, for example example.com.' };
  if (input.length > MAX_URL_LENGTH) return { ok: false, error: `That URL is too long (max ${MAX_URL_LENGTH} characters).` };
  // Strip control characters that browsers silently drop — they are used to disguise "java\tscript:".
  input = input.replace(/[\u0000-\u001f\u007f]/g, '');
  if (/\s/.test(input)) return { ok: false, error: 'A URL can’t contain spaces. Check for a typo or a stray space.' };

  const scheme = input.match(SCHEME_RE)?.[1]?.toLowerCase();
  if (scheme && DANGEROUS.includes(scheme)) {
    return { ok: false, error: `${scheme}: URLs are not allowed. Only http:// and https:// web pages can be tested.` };
  }

  let note: string | undefined;
  if (input.startsWith('//')) {
    input = `https:${input}`;
    note = 'Added https:';
  } else if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) {
    // "mailto:x", "ftp:x" etc. have a scheme but no "//"; "localhost:8080" looks like one but is a host.
    if (scheme && !/^[a-z0-9.-]+:\d+(?:[/?#]|$)/i.test(input)) {
      return { ok: false, error: `${scheme}: links can’t be embedded. Only http:// and https:// web pages can be tested.` };
    }
    input = `https://${input}`;
    note = 'Added https://';
  }

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return { ok: false, error: 'That doesn’t look like a valid URL. Try something like https://example.com/page.' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, error: `${url.protocol} URLs can’t be tested. Only http:// and https:// web pages can be embedded.` };
  }
  if (url.username || url.password) {
    return { ok: false, error: 'Remove the username and password from the URL — credentials in links are blocked by browsers in iframes.' };
  }

  const host = url.hostname;
  const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
  const isLocal = host === 'localhost' || host.endsWith('.localhost');
  if (!host) return { ok: false, error: 'The URL is missing a domain name.' };
  if (!isIp && !isLocal) {
    const labels = host.split('.');
    const tld = labels.at(-1) ?? '';
    if (labels.length < 2 || labels.some((l) => !l)) {
      return { ok: false, error: `“${host}” is not a complete domain. Include the ending, e.g. ${host.replace(/\.+$/, '') || 'example'}.com.` };
    }
    if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i.test(tld)) {
      return { ok: false, error: `“.${tld}” is not a valid domain ending.` };
    }
  }

  return { ok: true, url: url.href, note };
}
