/**
 * The in-browser half of the test: a hidden iframe with a timeout, plus a no-cors reachability ping.
 *
 * What the browser lets us learn (verified in Chromium and Firefox):
 *  - `load` fires for allowed AND blocked pages (blocked ones get an error page), so it is only a timing.
 *  - contentDocument / location are off-limits for any cross-origin page, blocked or not.
 *  - `contentWindow.length` (number of child frames) IS readable cross-origin. A browser error page
 *    never contains frames, so a count > 0 proves a real document rendered. 0 proves nothing.
 */
import type { ProbeResult, ReachResult } from '../lib/verdict.ts';

/** Permissions for both the hidden probe and the preview. No allow-top-navigation: the page can't hijack this tab. */
export const SANDBOX = 'allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-presentation allow-pointer-lock allow-modals';

export const isMixedContent = (url: string) => location.protocol === 'https:' && url.startsWith('http:');

const CHILD_FRAME_WATCH_MS = 2500;

export function probeIframe(url: string, timeoutMs: number, signal: AbortSignal): Promise<ProbeResult> {
  if (isMixedContent(url)) return Promise.resolve({ outcome: 'skipped-mixed-content', loadMs: null, childFrames: 0, timeoutMs });

  return new Promise((resolve, reject) => {
    const frame = document.createElement('iframe');
    frame.setAttribute('sandbox', SANDBOX);
    frame.setAttribute('referrerpolicy', 'strict-origin-when-cross-origin');
    frame.setAttribute('loading', 'eager');
    frame.setAttribute('aria-hidden', 'true');
    frame.setAttribute('tabindex', '-1');
    frame.title = 'Hidden embedding test';
    Object.assign(frame.style, { position: 'absolute', left: '-9999px', top: '0', width: '1px', height: '1px', border: '0', visibility: 'hidden' });

    const started = performance.now();
    let loadMs: number | null = null;
    let childFrames = 0;
    let settled = false;
    const timers: number[] = [];

    const countFrames = () => {
      try {
        childFrames = Math.max(childFrames, frame.contentWindow?.length ?? 0);
      } catch {
        /* never throws today, but stay safe */
      }
    };
    const finish = (result: ProbeResult | Error) => {
      if (settled) return;
      settled = true;
      timers.forEach(clearTimeout);
      signal.removeEventListener('abort', onAbort);
      frame.remove();
      if (result instanceof Error) reject(result);
      else resolve(result);
    };
    const onAbort = () => finish(new DOMException('Test cancelled', 'AbortError'));

    frame.addEventListener('load', () => {
      if (loadMs !== null) return;
      loadMs = performance.now() - started;
      countFrames();
      // Pages often add frames (players, widgets) shortly after load — watch a little longer.
      for (let t = 250; t <= CHILD_FRAME_WATCH_MS; t += 250) timers.push(window.setTimeout(countFrames, t));
      timers.push(window.setTimeout(() => finish({ outcome: 'load', loadMs, childFrames, timeoutMs }), CHILD_FRAME_WATCH_MS + 20));
    });
    frame.addEventListener('error', () => finish({ outcome: 'error', loadMs: performance.now() - started, childFrames, timeoutMs }));
    timers.push(
      window.setTimeout(() => {
        if (loadMs === null) finish({ outcome: 'timeout', loadMs: null, childFrames, timeoutMs });
      }, timeoutMs),
    );
    signal.addEventListener('abort', onAbort);

    // src before insertion, so no extra load event fires for the initial about:blank.
    frame.src = url;
    document.body.append(frame);
  });
}

/** Opaque no-cors request: resolves if the server answered at all, rejects on DNS/TLS/connection errors. */
export async function checkReachable(url: string, signal: AbortSignal): Promise<ReachResult> {
  if (isMixedContent(url)) return 'not-run';
  try {
    await fetch(url, {
      mode: 'no-cors',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'follow',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.any([signal, AbortSignal.timeout(8000)]),
    });
    return 'reachable';
  } catch (error) {
    if (signal.aborted) throw error;
    return 'unreachable';
  }
}
