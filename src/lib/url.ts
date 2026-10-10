/**
 * URL helpers that respect the deployment base path (/VideoTester/ on GitHub Pages).
 * Always build internal links with `url()` — never hard-code "/VideoTester".
 */

const base = import.meta.env.BASE_URL.replace(/\/+$/, '');

const isExternal = (path: string) => /^[a-z][a-z0-9+.-]*:/i.test(path) || path.startsWith('//');

/** Prefix a site-relative path ("/watch/") with the base path. */
export function url(path = '/'): string {
  if (!path) return `${base}/`;
  if (isExternal(path) || path.startsWith('#')) return path;
  const normalised = path.startsWith('/') ? path : `/${path}`;
  if (base && (normalised === base || normalised.startsWith(`${base}/`))) return normalised;
  return `${base}${normalised}`;
}

/** Absolute URL for canonical tags, Open Graph and JSON-LD. */
export function absoluteUrl(path: string, site: URL | string | undefined = import.meta.env.SITE): string {
  if (/^https?:\/\//i.test(path)) return path;
  return new URL(url(path), site).href;
}

