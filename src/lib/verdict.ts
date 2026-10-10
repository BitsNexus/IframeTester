/**
 * Combines every signal into one answer with an honest confidence level.
 *
 * Signals, strongest first:
 *  1. Response headers from the server check (X-Frame-Options, CSP frame-ancestors) evaluated
 *     with the browser's own rules (policy.ts) — the only thing that can prove "blocked".
 *  2. Mixed content: an https:// page can never frame an http:// page.
 *  3. The live iframe: child frames appearing inside it prove a real document rendered
 *     (a browser's "refused to connect" page has none). A `load` event proves nothing —
 *     browsers fire it for blocked pages too, on purpose, so sites can't be probed.
 *  4. Timeouts and a no-cors reachability ping, which only explain failures.
 *
 * Pure — no DOM — so it runs under node --test.
 */
import type { CheckFailure, CheckSuccess } from './api-types.ts';
import { evaluateFraming, formatSources, type Audience, type FramingResult } from './policy.ts';

export type Status = 'embeddable' | 'blocked' | 'unknown';
export type Confidence = 'high' | 'medium' | 'low';
export type FindingState = 'pass' | 'fail' | 'warn' | 'info';

export interface ProbeResult {
  outcome: 'load' | 'timeout' | 'error' | 'skipped-mixed-content';
  loadMs: number | null;
  /** Highest `contentWindow.length` seen after load. > 0 means a real document rendered. */
  childFrames: number;
  timeoutMs: number;
}

export type ReachResult = 'reachable' | 'unreachable' | 'not-run';

export type ServerOutcome =
  | { kind: 'disabled' }
  | { kind: 'not-configured' }
  | { kind: 'unavailable'; error: string }
  | { kind: 'done'; data: CheckSuccess | CheckFailure };

export interface VerdictInput {
  requestedUrl: string;
  /** Origin this tester runs on — where the live iframe test happens. */
  testerOrigin: string;
  /** Optional: the site the user wants to embed on. Header rules are judged for it. */
  embedderOrigin?: string;
  probe: ProbeResult;
  reach: ReachResult;
  server: ServerOutcome;
}

export interface Finding {
  state: FindingState;
  title: string;
  detail: string;
}

export interface Verdict {
  status: Status;
  confidence: Confidence;
  headline: string;
  summary: string;
  reasonsTitle: string;
  reasons: string[];
  /** Concrete next steps, e.g. "use the https:// address". */
  tips: string[];
  findings: Finding[];
  framing: FramingResult | null;
  timedOut: boolean;
}

export const STATUS_LABEL: Record<Status, string> = {
  embeddable: 'Embeddable',
  blocked: 'Embedding Blocked',
  unknown: 'Could Not Determine',
};

export const CONFIDENCE_TEXT: Record<Confidence, string> = {
  high: 'Based on the page’s own security headers — the same rules your browser enforces.',
  medium: 'Most signals agree, but something could change the result in a real embed.',
  low: 'Browsers hide cross-origin frame details, so there isn’t enough evidence for a firm answer.',
};

function describeAudience(audience: Audience): string {
  switch (audience.kind) {
    case 'anyone':
      return 'any website';
    case 'nobody':
      return 'no website at all (not even itself)';
    case 'same-origin':
      return `only pages on ${audience.origin}`;
    case 'listed':
      return `only ${audience.sources.join(', ')}`;
  }
}

/** Plain-language reasons the headers block the chosen embedder. */
function blockingReasons(framing: FramingResult): string[] {
  const reasons: string[] = [];
  if (framing.decidedBy === 'csp') {
    for (const entry of framing.csp.enforced.filter((e) => !e.allows)) {
      const list = entry.sources.map((s) => s.toLowerCase());
      if (list.length === 0 || (list.length === 1 && list[0] === "'none'")) reasons.push(`CSP frame-ancestors 'none' — no site may frame this page.`);
      else if (list.length === 1 && list[0] === "'self'") reasons.push(`CSP frame-ancestors 'self' — only the site itself may frame this page.`);
      else reasons.push(`CSP frame-ancestors restriction — only ${formatSources(entry.sources)} may frame this page.`);
    }
    if (framing.xfo.ignored) reasons.push(`X-Frame-Options: ${framing.xfo.raw} is also set (browsers ignore it when frame-ancestors is present).`);
  } else if (framing.decidedBy === 'xfo') {
    const raw = framing.xfo.raw ?? '';
    if (framing.xfo.kind === 'deny') reasons.push(`X-Frame-Options: ${raw} — no site may frame this page.`);
    else if (framing.xfo.kind === 'sameorigin') reasons.push(`X-Frame-Options: ${raw} — only pages on the same site may frame it.`);
    else reasons.push(`X-Frame-Options: ${raw} — conflicting values, which browsers treat as DENY.`);
  }
  reasons.push('The site owner has chosen to block embedding on other websites.');
  return reasons;
}

function headerFindings(data: CheckSuccess, framing: FramingResult, embedderLabel: string): Finding[] {
  const out: Finding[] = [];
  const { xfo, csp } = framing;

  // X-Frame-Options
  if (xfo.kind === 'absent') out.push({ state: 'pass', title: 'X-Frame-Options: not set', detail: 'No legacy framing restriction.' });
  else if (xfo.ignored)
    out.push({ state: 'info', title: `X-Frame-Options: ${xfo.raw}`, detail: 'Ignored by browsers, because the Content-Security-Policy has a frame-ancestors directive, which takes priority.' });
  else if (xfo.kind === 'allow-from')
    out.push({ state: 'warn', title: `X-Frame-Options: ${xfo.raw}`, detail: 'ALLOW-FROM is obsolete — Chrome, Edge, Firefox and Safari ignore it, so it does not restrict anything. Use CSP frame-ancestors instead.' });
  else if (xfo.kind === 'allowall' || xfo.kind === 'unrecognised')
    out.push({ state: 'info', title: `X-Frame-Options: ${xfo.raw}`, detail: 'Not a recognised value, so browsers ignore it.' });
  else
    out.push({
      state: xfo.allows ? 'pass' : 'fail',
      title: `X-Frame-Options: ${xfo.raw}`,
      detail: xfo.allows ? `Allows ${embedderLabel}.` : xfo.kind === 'sameorigin' ? 'Only pages on the same origin may frame this page.' : 'Blocks framing on every site.',
    });

  // CSP frame-ancestors
  if (csp.enforced.length === 0) {
    out.push({
      state: 'pass',
      title: 'CSP frame-ancestors: not set',
      detail: data.csp ? 'A Content-Security-Policy is present, but it has no frame-ancestors directive.' : 'No Content-Security-Policy header.',
    });
  }
  for (const entry of csp.enforced) {
    out.push({
      state: entry.allows ? 'pass' : 'fail',
      title: `CSP frame-ancestors ${formatSources(entry.sources)}`,
      detail: `Allows ${describeAudience(entry.audience)}. ${entry.allows ? `That includes ${embedderLabel}.` : `That excludes ${embedderLabel}.`}`,
    });
  }
  for (const entry of csp.reportOnly) {
    out.push({
      state: 'info',
      title: `Report-only frame-ancestors ${formatSources(entry.sources)}`,
      detail: 'Content-Security-Policy-Report-Only never blocks — it only sends reports. It may be enforced in the future.',
    });
  }

  // Response
  if (data.redirects.length) {
    out.push({ state: 'info', title: `${data.redirects.length} redirect${data.redirects.length > 1 ? 's' : ''}`, detail: `Ended at ${data.finalUrl}. The headers above are from that final page.` });
  }
  if (data.botProtection) {
    out.push({
      state: 'warn',
      title: `Bot protection: ${data.botProtection} (HTTP ${data.status})`,
      detail: 'The site answered our server with a bot check, so the headers above may not be the ones real visitors get.',
    });
  } else if (data.status >= 400) {
    out.push({ state: 'warn', title: `HTTP ${data.status} ${data.statusText}`.trim(), detail: 'The page returned an error status. An iframe would show that error page.' });
  } else {
    out.push({ state: 'pass', title: `HTTP ${data.status} ${data.statusText}`.trim(), detail: `Fetched in ${data.fetchMs} ms, as a cross-site iframe request.` });
  }
  const disposition = data.headers['content-disposition'] ?? '';
  if (/^\s*attachment/i.test(disposition)) {
    out.push({ state: 'warn', title: 'Content-Disposition: attachment', detail: 'The URL downloads a file instead of displaying a page, so an iframe would trigger a download.' });
  }

  // HTML
  const html = data.html;
  if (html?.frameBusting.length) {
    out.push({
      state: 'warn',
      title: 'Frame-busting script found',
      detail: `Inline code (${html.frameBusting.join(', ')}) tries to escape or hide the page when framed. Modern browsers block most top-window redirects, but the page may stay blank.`,
    });
  } else if (html?.frameDetection.length) {
    out.push({ state: 'info', title: 'Frame-detection script found', detail: `Inline code checks whether it is framed (${html.frameDetection.join(', ')}). Usually harmless — often analytics.` });
  }
  if (html?.metaXfo) {
    out.push({ state: 'info', title: `<meta> X-Frame-Options: ${html.metaXfo}`, detail: 'Browsers ignore X-Frame-Options in a <meta> tag — it only works as an HTTP header.' });
  }
  if (html?.metaCsp && /frame-ancestors/i.test(html.metaCsp)) {
    out.push({ state: 'info', title: '<meta> CSP with frame-ancestors', detail: 'Browsers ignore frame-ancestors in a <meta> tag — it only works as an HTTP header.' });
  }
  if (html?.metaRefresh) {
    out.push({ state: 'warn', title: 'Meta refresh redirect', detail: `The page redirects itself to ${html.metaRefresh}. That page’s headers were not checked.` });
  }
  return out;
}

function probeFinding(probe: ProbeResult): Finding {
  if (probe.outcome === 'skipped-mixed-content') {
    return { state: 'fail', title: 'Live iframe test: blocked (mixed content)', detail: 'This tester runs on https://, and browsers never load http:// pages inside https:// pages.' };
  }
  if (probe.outcome === 'timeout') {
    return { state: 'warn', title: `Live iframe test: timed out after ${probe.timeoutMs / 1000} s`, detail: 'The frame never finished loading.' };
  }
  if (probe.childFrames > 0) {
    return {
      state: 'pass',
      title: `Live iframe test: page rendered (${probe.childFrames} sub-frame${probe.childFrames > 1 ? 's' : ''})`,
      detail: `Loaded in ${fmtMs(probe.loadMs)} and created its own frames — only a real document can do that; a blocked frame shows an empty error page.`,
    };
  }
  return {
    state: 'info',
    title: `Live iframe test: load event after ${fmtMs(probe.loadMs)}`,
    detail: 'Browsers fire the load event for blocked frames too, and hide cross-origin content, so this alone can’t confirm the page is visible.',
  };
}

export const fmtMs = (ms: number | null) => (ms == null ? '—' : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(1)} sec`);

export function decide(input: VerdictInput): Verdict {
  const { probe, server } = input;
  const embedder = input.embedderOrigin || null;
  const embedderLabel = embedder ? new URL(embedder).origin : 'other websites';
  const findings: Finding[] = [];
  const tips: string[] = [];

  const data = server.kind === 'done' && server.data.ok ? server.data : null;
  const failure = server.kind === 'done' && !server.data.ok ? server.data : null;
  const framing = data
    ? evaluateFraming({ xFrameOptions: data.xFrameOptions, csp: data.csp, cspReportOnly: data.cspReportOnly, resourceUrl: data.finalUrl, embedderOrigin: embedder ?? undefined })
    : null;

  // --- Evidence list -----------------------------------------------------------------------
  if (data && framing) findings.push(...headerFindings(data, framing, embedderLabel));
  else if (failure) findings.push({ state: 'warn', title: 'Server header check failed', detail: failure.error });
  else if (server.kind === 'unavailable') findings.push({ state: 'warn', title: 'Server header check unavailable', detail: server.error });
  else if (server.kind === 'disabled') findings.push({ state: 'info', title: 'Server header check: off', detail: 'Only browser signals were used. Turn on “Check headers on server” for a definite answer.' });
  else findings.push({ state: 'info', title: 'Server header check: not configured', detail: 'This copy of the tool has no header-check API, so only browser signals were used.' });

  findings.push(probeFinding(probe));
  if (input.reach === 'unreachable') {
    findings.push({ state: 'warn', title: 'Reachability: failed', detail: 'Your browser could not connect to the site at all (offline, DNS error, invalid certificate, or blocked by an extension).' });
  } else if (input.reach === 'reachable') {
    findings.push({ state: 'info', title: 'Reachability: the site responded', detail: 'Your browser got a response, but its headers are hidden from web pages.' });
  }

  const target = new URL(data?.finalUrl ?? input.requestedUrl);
  const embedIsHttps = new URL(embedder ?? input.testerOrigin).protocol === 'https:';
  const mixed = embedIsHttps && new URL(input.requestedUrl).protocol === 'http:';
  const timedOut = probe.outcome === 'timeout';

  const result = (status: Status, confidence: Confidence, headline: string, summary: string, reasonsTitle: string, reasons: string[]): Verdict => ({
    status,
    confidence: status === 'unknown' ? 'low' : confidence,
    headline,
    summary,
    reasonsTitle,
    reasons,
    tips,
    findings,
    framing,
    timedOut,
  });

  // --- 1. Mixed content: decided by the browser before any request is made -------------------
  if (mixed) {
    const httpsVersion = data && target.protocol === 'https:' ? target.href : input.requestedUrl.replace(/^http:/, 'https:');
    tips.push(`Try the secure address instead: ${httpsVersion}`);
    const reasons = ['Mixed content: browsers never load an http:// page inside an https:// page.'];
    if (framing && !framing.allowed) reasons.push(...blockingReasons(framing).slice(0, -1));
    return result('blocked', 'high', STATUS_LABEL.blocked, 'This http:// address can’t be shown inside a secure (https://) website.', 'Why', reasons);
  }

  // --- 2. Headers from the server check ------------------------------------------------------
  if (data && framing) {
    if (data.botProtection) {
      if (probe.childFrames > 0) {
        return result(
          'embeddable',
          'medium',
          STATUS_LABEL.embeddable,
          'The page rendered inside the live iframe, but the site hid its real headers from our server behind a bot check.',
          'Keep in mind',
          [`${data.botProtection} answered our server instead of the real page.`, 'Visitors may also see a “verify you are human” check inside the frame.'],
        );
      }
      return result(
        'unknown',
        'low',
        STATUS_LABEL.unknown,
        'The site answered our server with a bot check, so its real headers are hidden, and browsers don’t reveal whether a frame was blocked.',
        'Possible reasons',
        [`${data.botProtection} bot protection (HTTP ${data.status})`, 'Browser security restrictions hide cross-origin frame content', 'Open the preview to see what visitors would get'],
      );
    }

    if (!framing.allowed) {
      tips.push(
        framing.audience.kind === 'nobody'
          ? 'Only the site owner can change this. Link to the page (or open it in a popup) instead of embedding it.'
          : `The headers allow ${describeAudience(framing.audience)} to embed it. Ask the site owner to add your domain, or link to the page instead.`,
      );
      if (/youtube\.com$|youtu\.be$/.test(target.hostname) && !target.pathname.startsWith('/embed/')) tips.push('For YouTube videos, use the embed URL: https://www.youtube.com/embed/VIDEO_ID');
      return result(
        'blocked',
        'high',
        STATUS_LABEL.blocked,
        embedder ? `The page’s security headers don’t allow ${embedderLabel} to embed it.` : 'The page’s security headers tell browsers not to show it inside other websites.',
        'Reasons',
        blockingReasons(framing),
      );
    }

    // Headers allow it — look for anything that would still spoil a real embed.
    if (/^\s*attachment/i.test(data.headers['content-disposition'] ?? '')) {
      return result('unknown', 'low', 'Downloads Instead of Displaying', 'Framing is allowed, but this URL sends a file download rather than a page.', 'What happens', [
        'Content-Disposition: attachment makes browsers download the file.',
        'An iframe pointing here shows nothing and may start a download.',
      ]);
    }
    const caveats: string[] = [];
    if (data.status >= 400) caveats.push(`The page returned HTTP ${data.status}, so an embed would show that error page (a working page could send different headers).`);
    if (data.html?.frameBusting.length) caveats.push('Inline frame-busting code may hide the page or try to break out of the frame.');
    if (data.html?.metaRefresh) caveats.push(`The page redirects itself to ${data.html.metaRefresh}, whose headers were not checked.`);
    if (timedOut) caveats.push(`The live iframe didn’t finish loading within ${probe.timeoutMs / 1000} seconds — the site may be slow.`);
    if (probe.outcome === 'error') caveats.push('The live iframe reported a loading error.');

    const allowedForOthersOnly = embedder && framing.audience.kind !== 'anyone';
    const summary = allowedForOthersOnly
      ? `Allowed for ${embedderLabel}. Other websites are blocked (${describeAudience(framing.audience)}).`
      : probe.childFrames > 0
        ? 'The page loaded inside an iframe and rendered. No restrictions detected.'
        : 'The page loaded inside an iframe. No obvious restrictions detected.';
    const why = [framing.decidedBy === 'none' ? 'No X-Frame-Options or CSP frame-ancestors restriction.' : `Framing is allowed for ${embedderLabel} by the page’s headers.`];
    if (probe.outcome === 'load') why.push(`The live test frame loaded in ${fmtMs(probe.loadMs)}.`);
    return caveats.length
      ? result('embeddable', 'medium', STATUS_LABEL.embeddable, summary, 'Keep in mind', caveats)
      : result('embeddable', 'high', STATUS_LABEL.embeddable, summary, 'Why', why);
  }

  // --- 3. Browser-only signals ---------------------------------------------------------------
  const noHeaders =
    server.kind === 'disabled'
      ? 'The server header check is turned off'
      : failure?.code === 'blocked-host'
        ? 'Local and private addresses can’t be checked by the server'
        : 'The page’s headers could not be read';

  if (failure?.code === 'dns' || failure?.code === 'tls' || failure?.code === 'too-many-redirects') {
    const title = failure.code === 'dns' ? 'Site Not Found' : failure.code === 'tls' ? 'Certificate Problem' : 'Redirect Loop';
    return result('unknown', 'low', title, failure.error, 'What this means', [
      'An iframe pointing here would show the browser’s error page, not the site.',
      failure.code === 'dns' ? 'Check the spelling of the domain.' : 'The site needs to fix this before it can be embedded.',
    ]);
  }

  if (probe.childFrames > 0) {
    return result('embeddable', 'medium', STATUS_LABEL.embeddable, 'The page rendered inside the live iframe — it created its own frames, which a blocked page can’t do.', 'Keep in mind', [
      `${noHeaders}, so other sites may be treated differently (for example with frame-ancestors allow-lists).`,
      'What rendered could be a login, cookie or “verify you are human” page — check the preview.',
    ]);
  }

  if (timedOut) {
    return result('unknown', 'low', 'Request Timed Out', `The iframe didn’t finish loading within ${probe.timeoutMs / 1000} seconds.`, 'Possible reasons', [
      'Network issue',
      'Slow website',
      'Embedding restrictions',
    ]);
  }

  if (input.reach === 'unreachable') {
    return result('unknown', 'low', STATUS_LABEL.unknown, 'Your browser couldn’t reach this site at all.', 'Possible reasons', [
      'The site is down or the domain doesn’t exist',
      'Your network, firewall or an ad blocker blocked it',
      'An invalid HTTPS certificate',
    ]);
  }

  return result('unknown', 'low', STATUS_LABEL.unknown, 'Browser security restrictions prevented a definitive result.', 'Why', [
    'The frame fired its load event — but browsers fire it for blocked pages too.',
    'Browsers hide what’s inside cross-origin frames, so this page can’t look.',
    `${noHeaders}. Open the preview to see it yourself.`,
  ]);
}
