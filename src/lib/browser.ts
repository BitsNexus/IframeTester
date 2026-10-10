/** Friendly browser / OS names for the diagnostics panel (same rules as the Video Tester). */

export function getBrowserName(ua: string): string {
  const match = (re: RegExp) => ua.match(re)?.[1]?.split('.')[0];
  let v: string | undefined;
  if ((v = match(/Edg(?:e|A|iOS)?\/([\d.]+)/))) return `Microsoft Edge ${v}`;
  if ((v = match(/OPR\/([\d.]+)/))) return `Opera ${v}`;
  if ((v = match(/SamsungBrowser\/([\d.]+)/))) return `Samsung Internet ${v}`;
  if ((v = match(/Firefox\/([\d.]+)/)) || (v = match(/FxiOS\/([\d.]+)/))) return `Firefox ${v}`;
  if ((v = match(/CriOS\/([\d.]+)/))) return `Chrome (iOS) ${v}`;
  if ((v = match(/Chrome\/([\d.]+)/))) return `Chrome ${v}`;
  if ((v = match(/Version\/([\d.]+).*Safari/))) return `Safari ${v}`;
  return 'Unknown browser';
}

export function getOsName(ua: string): string {
  if (/Windows NT/.test(ua)) return 'Windows';
  if (/Android/.test(ua)) return 'Android';
  if (/iPhone|iPad|iPod/.test(ua)) return 'iOS / iPadOS';
  if (/Mac OS X|Macintosh/.test(ua)) return 'macOS';
  if (/CrOS/.test(ua)) return 'ChromeOS';
  if (/Linux/.test(ua)) return 'Linux';
  return 'Unknown OS';
}
