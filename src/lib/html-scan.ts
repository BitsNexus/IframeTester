/**
 * Looks through the start of an HTML document for framing-related markup the headers don't show:
 * frame-busting scripts and <meta> tags that people *think* block framing (browsers ignore them).
 * A regex scan of inline code — external scripts aren't fetched, so absence proves nothing.
 */
import type { HtmlScan } from './api-types.ts';

/** Code that actively escapes or hides from a frame. */
const BUSTING: Array<[string, RegExp]> = [
  ['top.location assignment', /\b(?:window\.)?top\.location(?:\.href)?\s*=(?!=)/],
  ['top.location.replace()', /\b(?:window\.)?top\.location\.(?:replace|assign)\s*\(/],
  ['parent.location assignment', /\b(?:window\.)?parent\.location(?:\.href)?\s*=(?!=)/],
  ['anti-clickjacking style', /id\s*=\s*["']?antiClickjack|html\s*\{\s*display\s*:\s*none\s*!?\s*(?:important)?\s*;?\s*\}/i],
];

/** Code that merely notices it is framed (common in analytics and embeds, usually harmless). */
const DETECTION: Array<[string, RegExp]> = [
  ['top !== self check', /\b(?:window\.)?(?:top|self|parent)\s*!==?\s*(?:window\.)?(?:top|self|window)\b|\bwindow\s*!==?\s*(?:window\.)?(?:top|parent)\b/],
  ['window.frameElement check', /\b(?:window|self)\.frameElement\b/],
];

const decodeEntities = (s: string) =>
  s
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .trim();

function metaContent(html: string, httpEquiv: string): string | null {
  const tags = html.match(/<meta\b[^>]*>/gi) ?? [];
  for (const tag of tags) {
    const equiv = tag.match(/http-equiv\s*=\s*["']?([^"'\s>]+)/i)?.[1];
    if (equiv?.toLowerCase() !== httpEquiv) continue;
    const content = tag.match(/content\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const value = content?.[1] ?? content?.[2] ?? content?.[3];
    if (value != null) return decodeEntities(value);
  }
  return null;
}

export function scanHtml(html: string, bytes = html.length): HtmlScan {
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1] ?? '').join('\n');
  const styles = [...html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)].map((m) => m[1] ?? '').join('\n');
  const code = `${scripts}\n${styles}\n${(html.match(/<[^>]+\bid\s*=\s*["']?antiClickjack[^>]*>/gi) ?? []).join('\n')}`;
  const found = (list: Array<[string, RegExp]>) => list.filter(([, re]) => re.test(code)).map(([label]) => label);

  const refresh = metaContent(html, 'refresh');
  const refreshUrl = refresh?.match(/url\s*=\s*['"]?([^'";]+)/i)?.[1]?.trim() ?? null;
  const title = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1];

  return {
    bytes,
    title: title ? decodeEntities(title.replace(/\s+/g, ' ')).slice(0, 200) || null : null,
    metaCsp: metaContent(html, 'content-security-policy'),
    metaXfo: metaContent(html, 'x-frame-options'),
    metaRefresh: refreshUrl,
    frameBusting: found(BUSTING),
    frameDetection: found(DETECTION),
  };
}
