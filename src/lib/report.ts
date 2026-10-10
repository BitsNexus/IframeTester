/**
 * Diagnostics rows (shown in the panel) and the plain-text report (Copy report).
 * Both come from the same data so they never disagree.
 */
import type { CheckSuccess } from './api-types.ts';
import { fmtMs, type ProbeResult, type ServerOutcome, type Verdict } from './verdict.ts';

export interface DiagnosticsInput {
  url: string;
  verdict: Verdict;
  server: ServerOutcome;
  probe: ProbeResult;
  browser: string;
  embedder: string;
  testedAt: Date;
}

export interface Row {
  label: string;
  value: string;
  mono?: boolean;
  tone?: 'pass' | 'fail' | 'warn';
}

const SYMBOL = { embeddable: '✓', blocked: '✕', unknown: '⚠' } as const;
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

export function frameAncestorsOf(csp: string | null): string | null {
  if (!csp) return null;
  const found = csp
    .split(',')
    .map((policy) => policy.split(';').map((d) => d.trim()).find((d) => /^frame-ancestors(\s|$)/i.test(d)))
    .filter(Boolean);
  return found.length ? found.join(' , ') : null;
}

export function diagnosticsRows(input: DiagnosticsInput): Row[] {
  const { verdict, server, probe } = input;
  const data: CheckSuccess | null = server.kind === 'done' && server.data.ok ? server.data : null;
  const tone = verdict.status === 'embeddable' ? 'pass' : verdict.status === 'blocked' ? 'fail' : 'warn';

  const rows: Row[] = [
    { label: 'URL', value: input.url, mono: true },
    { label: 'Status', value: `${SYMBOL[verdict.status]} ${verdict.headline}`, tone },
    { label: 'Confidence', value: cap(verdict.confidence) },
    {
      label: 'Load Time',
      value:
        probe.outcome === 'skipped-mixed-content'
          ? 'Not loaded (mixed content)'
          : probe.outcome === 'timeout'
            ? `Timed out after ${probe.timeoutMs / 1000} sec`
            : `${fmtMs(probe.loadMs)}${probe.childFrames ? ` · ${probe.childFrames} sub-frame${probe.childFrames > 1 ? 's' : ''}` : ''}`,
    },
  ];

  if (data) {
    if (data.finalUrl !== data.requestedUrl) rows.push({ label: 'Final URL', value: data.finalUrl, mono: true });
    rows.push({ label: 'HTTP Status', value: `${data.status} ${data.statusText}`.trim(), tone: data.status >= 400 ? 'warn' : undefined });
    if (data.redirects.length) rows.push({ label: 'Redirects', value: data.redirects.map((r) => `${r.status} → ${r.location}`).join('\n'), mono: true });
    const fa = frameAncestorsOf(data.csp);
    rows.push({ label: 'X-Frame-Options', value: data.xFrameOptions ?? '(not set)', mono: true, tone: verdict.framing?.xfo.ignored ? undefined : verdict.framing?.xfo.allows === false ? 'fail' : undefined });
    rows.push({ label: 'CSP frame-ancestors', value: fa ?? '(not set)', mono: true, tone: verdict.framing?.csp.enforced.some((e) => !e.allows) ? 'fail' : undefined });
    const faReport = frameAncestorsOf(data.cspReportOnly);
    if (faReport) rows.push({ label: 'CSP report-only', value: faReport, mono: true });
    if (data.contentType) rows.push({ label: 'Content-Type', value: data.contentType, mono: true });
    if (data.html?.title) rows.push({ label: 'Page title', value: data.html.title });
  } else {
    const why =
      server.kind === 'done' && !server.data.ok
        ? server.data.error
        : server.kind === 'unavailable'
          ? server.error
          : server.kind === 'disabled'
            ? 'Server check turned off'
            : 'Server check not configured';
    rows.push({ label: 'Headers', value: `Not available — ${why}`, tone: 'warn' });
  }

  rows.push(
    { label: 'Checked for', value: input.embedder || 'Any other website' },
    { label: 'Mode', value: data ? 'Browser + server header check' : 'Browser only' },
    { label: 'Browser', value: input.browser },
    { label: 'Tested', value: input.testedAt.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' }) },
  );
  return rows;
}

export function buildReport(input: DiagnosticsInput): string {
  const { verdict } = input;
  const lines = ['IFrame URL Tester — report', '='.repeat(26), ''];
  lines.push(`${SYMBOL[verdict.status]} ${verdict.headline} (${verdict.confidence} confidence)`, verdict.summary, '');
  if (verdict.reasons.length) lines.push(`${verdict.reasonsTitle}:`, ...verdict.reasons.map((r) => `  - ${r}`), '');
  if (verdict.tips.length) lines.push('Tips:', ...verdict.tips.map((t) => `  - ${t}`), '');
  lines.push('Diagnostics:');
  for (const row of diagnosticsRows(input)) lines.push(`  ${row.label}: ${row.value.replace(/\n/g, '\n    ')}`);
  lines.push('', 'Evidence:');
  const mark = { pass: '[ok]', fail: '[x]', warn: '[!]', info: '[i]' } as const;
  for (const f of verdict.findings) lines.push(`  ${mark[f.state]} ${f.title} — ${f.detail}`);
  if (input.server.kind === 'done' && input.server.data.ok) {
    lines.push('', 'Response headers:');
    for (const [name, value] of Object.entries(input.server.data.headers)) lines.push(`  ${name}: ${value}`);
  }
  return lines.join('\n');
}
