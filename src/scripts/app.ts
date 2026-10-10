/**
 * UI controller: reads the form, runs the server header check and the live iframe in parallel,
 * asks verdict.ts for the answer and renders it. All untrusted text goes in via textContent.
 */
import { normalizeUrlInput } from '../lib/validate.ts';
import { evaluateFraming } from '../lib/policy.ts';
import { decide, CONFIDENCE_TEXT, fmtMs, type ProbeResult, type ReachResult, type ServerOutcome, type Status, type Verdict } from '../lib/verdict.ts';
import { checkHeaders, hasCheckApi } from '../lib/api.ts';
import { buildReport, diagnosticsRows, type DiagnosticsInput } from '../lib/report.ts';
import { getBrowserName, getOsName } from '../lib/browser.ts';
import { addHistory, clearHistory, getHistory, getSettings, saveSettings, type HistoryEntry } from '../lib/storage.ts';
import { checkReachable, isMixedContent, probeIframe, SANDBOX } from './probe.ts';

type StepId = 'validate' | 'server' | 'iframe' | 'analyse';
type StepState = 'pending' | 'running' | 'pass' | 'fail' | 'warn' | 'skip' | 'done';

const $ = <T extends Element = HTMLElement>(selector: string, root: ParentNode = document) => {
  const el = root.querySelector<T>(selector);
  if (!el) throw new Error(`Missing element ${selector}`);
  return el;
};

const form = $<HTMLFormElement>('[data-form]');
const input = $<HTMLInputElement>('[data-url-input]');
const submit = $<HTMLButtonElement>('[data-submit]');
const submitLabel = $('[data-submit-label]');
const errorBox = $('#url-error');
const errorText = $('[data-error-text]');
const serverToggle = $<HTMLInputElement>('[data-server-toggle]');
const serverNote = $('[data-server-note]');
const embedderInput = $<HTMLInputElement>('[data-embedder-input]');
const timeoutSelect = $<HTMLSelectElement>('[data-timeout]');
const pasteButton = $<HTMLButtonElement>('[data-action="paste"]');
const historyBox = $('[data-history]');
const historyList = $('[data-history-list]');

const results = $('[data-results]');
const statusCard = $('[data-status-card]');
const headline = $('[data-headline]');
const summary = $('[data-summary]');
const resultHost = $('[data-result-host]');
const badges = $('[data-badges]');
const confidenceBadge = $('[data-confidence]');
const confidenceText = $('[data-confidence-text]');
const modeBadge = $('[data-mode]');
const reasonsBlock = $('[data-reasons-block]');
const reasonsTitle = $('[data-reasons-title]');
const reasonsList = $('[data-reasons]');
const tipsList = $('[data-tips]');
const actions = $('[data-actions]');
const openLink = $<HTMLAnchorElement>('[data-open-link]');
const findingsList = $('[data-findings]');
const diagnosticsBody = $('[data-diagnostics]');
const rawBlock = $<HTMLDetailsElement>('[data-raw-block]');
const rawHeaders = $('[data-raw-headers]');
const previewCard = $('[data-preview-card]');
const previewHost = $('[data-preview-host]');
const previewUrl = $('[data-preview-url]');
const previewStatus = $('[data-preview-status]');
const embedCode = $('[data-embed-code]');

const SYMBOL: Record<Status, string> = { embeddable: '✓', blocked: '✕', unknown: '⚠' };
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
const browserName = `${getBrowserName(navigator.userAgent)} on ${getOsName(navigator.userAgent)}`;

let controller: AbortController | null = null;
let current: { url: string; report: DiagnosticsInput } | null = null;
let testedUrl = '';

// ---------------------------------------------------------------------------------------------
// Settings & history
// ---------------------------------------------------------------------------------------------

const settings = getSettings();
serverToggle.checked = hasCheckApi && settings.server !== false;
serverToggle.disabled = !hasCheckApi;
if (settings.timeoutMs && [...timeoutSelect.options].some((o) => o.value === String(settings.timeoutMs))) timeoutSelect.value = String(settings.timeoutMs);
if (settings.embedder) embedderInput.value = settings.embedder;

function persistSettings() {
  saveSettings({ server: serverToggle.checked, timeoutMs: Number(timeoutSelect.value), embedder: embedderInput.value.trim() });
  updateServerNote();
}

function updateServerNote() {
  serverNote.textContent = !hasCheckApi
    ? 'The server header check isn’t set up on this copy of the tool, so results rely on browser signals only.'
    : serverToggle.checked
      ? 'Server mode is on: the URL is sent to our checking service, which fetches the page once to read its headers.'
      : 'Server mode is off: everything stays in your browser, but most results will be “Could Not Determine”.';
}

function renderHistory(list: HistoryEntry[] = getHistory()) {
  historyList.replaceChildren(
    ...list.map((entry) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'inline-flex max-w-[16rem] items-center gap-1.5 rounded-full bg-white/10 px-3 py-1 font-medium text-white ring-1 ring-white/15 hover:bg-white/20';
      button.title = `${entry.url} — ${entry.status}`;
      const dot = document.createElement('span');
      dot.className = `size-2 shrink-0 rounded-full ${entry.status === 'embeddable' ? 'bg-lime' : entry.status === 'blocked' ? 'bg-[#f97066]' : 'bg-[#fdb022]'}`;
      dot.setAttribute('aria-hidden', 'true');
      const label = document.createElement('span');
      label.className = 'truncate';
      label.textContent = entry.url.replace(/^https?:\/\//, '').replace(/\/$/, '');
      button.append(dot, label);
      button.addEventListener('click', () => {
        input.value = entry.url;
        void run(entry.url);
      });
      return button;
    }),
  );
  historyBox.hidden = list.length === 0;
}

// ---------------------------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------------------------

function icon(kind: 'pass' | 'fail' | 'warn' | 'info' | 'tip'): Node {
  const template = document.querySelector<HTMLTemplateElement>(`template[data-icon="${kind}"]`);
  return template ? template.content.firstElementChild!.cloneNode(true) : document.createTextNode('');
}

function setStep(id: StepId, state: StepState, detail: string) {
  const step = $(`[data-step="${id}"]`);
  $('.step-dot', step).dataset.stepState = state;
  $('[data-step-detail]', step).textContent = detail;
}

function showError(message: string, field: HTMLInputElement = input) {
  errorText.textContent = message;
  errorBox.hidden = false;
  field.setAttribute('aria-invalid', 'true');
  field.focus();
}

function clearError() {
  errorBox.hidden = true;
  input.removeAttribute('aria-invalid');
  embedderInput.removeAttribute('aria-invalid');
}

function setBusy(busy: boolean) {
  submit.disabled = busy;
  submitLabel.textContent = busy ? 'Testing…' : 'Test URL';
}

function resetResults(url: string) {
  statusCard.dataset.state = 'running';
  resultHost.textContent = url;
  resultHost.title = url;
  headline.textContent = 'Testing…';
  summary.textContent = 'Reading the page’s headers and loading it in a hidden iframe.';
  badges.hidden = true;
  confidenceText.textContent = '';
  reasonsBlock.hidden = true;
  tipsList.replaceChildren();
  actions.hidden = true;
  findingsList.replaceChildren(placeholder('Collecting evidence…'));
  diagnosticsBody.replaceChildren();
  rawBlock.hidden = true;
  hidePreview();
  for (const id of ['validate', 'server', 'iframe', 'analyse'] as StepId[]) setStep(id, 'pending', 'Waiting');
}

function placeholder(text: string) {
  const li = document.createElement('li');
  li.className = 'text-sm text-gray-500';
  li.textContent = text;
  return li;
}

function renderVerdict(verdict: Verdict, report: DiagnosticsInput) {
  statusCard.dataset.state = verdict.status;
  headline.textContent = `${SYMBOL[verdict.status]} ${verdict.headline}`;
  summary.textContent = verdict.summary;

  badges.hidden = false;
  confidenceBadge.dataset.status = verdict.confidence === 'high' ? 'pass' : verdict.confidence === 'medium' ? 'warn' : 'pending';
  confidenceBadge.textContent = `${verdict.confidence.charAt(0).toUpperCase()}${verdict.confidence.slice(1)} confidence`;
  confidenceText.textContent = CONFIDENCE_TEXT[verdict.confidence];
  const headerMode = report.server.kind === 'done' && report.server.data.ok;
  modeBadge.textContent = headerMode ? 'Server + browser' : 'Browser only';

  reasonsBlock.hidden = verdict.reasons.length === 0;
  reasonsTitle.textContent = verdict.reasonsTitle;
  reasonsList.replaceChildren(
    ...verdict.reasons.map((reason) => {
      const li = document.createElement('li');
      li.textContent = reason;
      return li;
    }),
  );
  tipsList.replaceChildren(
    ...verdict.tips.map((tip) => {
      const li = document.createElement('li');
      li.className = 'flex items-start gap-2 rounded-lg bg-pass-bg px-3 py-2 text-sm font-medium text-gray-800 ring-1 ring-pass-line';
      const text = document.createElement('span');
      text.textContent = tip;
      li.append(icon('tip'), text);
      return li;
    }),
  );

  findingsList.replaceChildren(
    ...verdict.findings.map((finding) => {
      const li = document.createElement('li');
      li.className = 'flex gap-3';
      const body = document.createElement('div');
      body.className = 'min-w-0';
      const title = document.createElement('p');
      title.className = 'text-sm font-bold break-words text-gray-900';
      title.textContent = finding.title;
      const detail = document.createElement('p');
      detail.className = 'mt-0.5 text-sm text-gray-600';
      detail.textContent = finding.detail;
      body.append(title, detail);
      li.append(icon(finding.state), body);
      return li;
    }),
  );

  diagnosticsBody.replaceChildren(
    ...diagnosticsRows(report).map((row) => {
      const tr = document.createElement('tr');
      const th = document.createElement('th');
      th.scope = 'row';
      th.textContent = row.label;
      const td = document.createElement('td');
      td.className =
        row.tone === 'pass' ? 'font-bold text-pass' : row.tone === 'fail' ? 'font-bold text-fail' : row.tone === 'warn' ? 'font-bold text-warn' : '';
      if (row.mono) {
        // URLs and header values can be very long: wrap anywhere and scroll after a few lines.
        const value = document.createElement('div');
        value.className = 'max-h-28 overflow-y-auto font-mono text-xs break-all whitespace-pre-line';
        value.textContent = row.value;
        td.append(value);
      } else {
        td.textContent = row.value;
      }
      tr.append(th, td);
      return tr;
    }),
  );

  const data = report.server.kind === 'done' && report.server.data.ok ? report.server.data : null;
  rawBlock.hidden = !data;
  rawHeaders.textContent = data ? Object.entries(data.headers).map(([name, value]) => `${name}: ${value}`).join('\n') || '(no framing-related headers)' : '';

  openLink.href = report.url;
  actions.hidden = false;
  embedCode.textContent = embedSnippet(report.url);
}

// ---------------------------------------------------------------------------------------------
// Preview
// ---------------------------------------------------------------------------------------------

const escapeAttr = (s: string) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

function embedSnippet(url: string) {
  return `<iframe src="${escapeAttr(url)}" width="100%" height="500" style="border:0" loading="lazy" allowfullscreen referrerpolicy="strict-origin-when-cross-origin" title="Embedded page"></iframe>`;
}

function setPreviewButtons(open: boolean) {
  document.querySelectorAll<HTMLButtonElement>('[data-action="toggle-preview"][aria-controls]').forEach((button) => {
    button.setAttribute('aria-expanded', String(open));
    const label = button.querySelector('[data-preview-label]');
    if (label) label.textContent = open ? 'Hide Preview' : 'Show Preview';
  });
}

function showPreview() {
  if (!testedUrl) return;
  previewCard.hidden = false;
  previewUrl.textContent = testedUrl;
  embedCode.textContent = embedSnippet(testedUrl);
  setPreviewButtons(true);
  if (isMixedContent(testedUrl)) {
    const msg = document.createElement('div');
    msg.className = 'absolute inset-0 grid place-items-center p-6 text-center text-sm font-medium text-gray-600';
    msg.textContent = 'Your browser refuses to load an http:// page inside this https:// page (mixed content). Try the https:// address.';
    previewHost.replaceChildren(msg);
    previewStatus.textContent = 'Blocked by browser';
    return;
  }
  const frame = document.createElement('iframe');
  frame.src = testedUrl;
  frame.title = `Preview of ${testedUrl}`;
  frame.className = 'absolute inset-0 size-full border-0 bg-white';
  frame.setAttribute('sandbox', SANDBOX);
  frame.setAttribute('allow', 'fullscreen; autoplay; encrypted-media; picture-in-picture; gamepad; clipboard-write');
  frame.setAttribute('allowfullscreen', '');
  frame.setAttribute('referrerpolicy', 'strict-origin-when-cross-origin');
  const started = performance.now();
  previewStatus.textContent = 'Loading…';
  frame.addEventListener('load', () => {
    previewStatus.textContent = `Load event after ${fmtMs(performance.now() - started)}`;
  });
  previewHost.replaceChildren(frame);
}

function hidePreview() {
  previewCard.hidden = true;
  previewHost.replaceChildren();
  setPreviewButtons(false);
}

// ---------------------------------------------------------------------------------------------
// Test run
// ---------------------------------------------------------------------------------------------

async function run(raw: string) {
  clearError();
  const validation = normalizeUrlInput(raw);
  if (!validation.ok) {
    showError(validation.error);
    return;
  }
  const url = validation.url;
  input.value = url;

  let embedder = '';
  const embedderRaw = embedderInput.value.trim();
  if (embedderRaw) {
    const e = normalizeUrlInput(embedderRaw);
    if (!e.ok) {
      (form.querySelector('[data-advanced]') as HTMLDetailsElement).open = true;
      showError(`Your website: ${e.error}`, embedderInput);
      return;
    }
    embedder = new URL(e.url).origin;
    embedderInput.value = embedder;
  }
  persistSettings();

  controller?.abort();
  controller = new AbortController();
  const { signal } = controller;
  testedUrl = url;
  const timeoutMs = Number(timeoutSelect.value) || 10000;

  results.hidden = false;
  resetResults(url);
  setBusy(true);
  setStep('validate', 'pass', validation.note ?? (url.startsWith('https:') ? 'Valid https URL' : 'Valid http URL'));
  const rect = results.getBoundingClientRect();
  if (rect.top > innerHeight * 0.6 || rect.top < 0) results.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });

  const useServer = hasCheckApi && serverToggle.checked;
  setStep('server', useServer ? 'running' : 'skip', useServer ? 'Fetching headers…' : hasCheckApi ? 'Turned off' : 'Not configured');
  setStep('iframe', 'running', 'Loading hidden iframe…');

  const serverTask: Promise<ServerOutcome> = !useServer
    ? Promise.resolve(hasCheckApi ? { kind: 'disabled' } : { kind: 'not-configured' })
    : checkHeaders(url, signal).then(
        (data): ServerOutcome => {
          if (data.ok) {
            const framing = evaluateFraming({ xFrameOptions: data.xFrameOptions, csp: data.csp, cspReportOnly: data.cspReportOnly, resourceUrl: data.finalUrl, embedderOrigin: embedder || undefined });
            if (data.botProtection) setStep('server', 'warn', `Bot check: ${data.botProtection}`);
            else if (framing.allowed) setStep('server', 'pass', framing.decidedBy === 'none' ? 'No framing restriction' : 'Headers allow framing');
            else setStep('server', 'fail', framing.decidedBy === 'csp' ? 'Blocked by frame-ancestors' : `X-Frame-Options: ${data.xFrameOptions}`);
          } else {
            setStep('server', 'warn', data.error);
          }
          return { kind: 'done', data };
        },
        (error: unknown): ServerOutcome => {
          if (signal.aborted) throw error;
          setStep('server', 'warn', 'Checking service unreachable');
          return { kind: 'unavailable', error: `The checking service couldn’t be reached (${error instanceof Error ? error.message : 'network error'}).` };
        },
      );

  const probeTask = probeIframe(url, timeoutMs, signal).then((probe) => {
    if (probe.outcome === 'skipped-mixed-content') setStep('iframe', 'fail', 'Blocked: http inside https');
    else if (probe.outcome === 'timeout') setStep('iframe', 'warn', `Timed out (${timeoutMs / 1000} s)`);
    else if (probe.childFrames > 0) setStep('iframe', 'pass', `Rendered · ${probe.childFrames} sub-frame${probe.childFrames > 1 ? 's' : ''}`);
    // A bare load event is neutral: blocked frames fire it too.
    else setStep('iframe', 'done', `Load event after ${fmtMs(probe.loadMs)}`);
    return probe;
  });

  try {
    const [server, probe] = await Promise.all([serverTask, probeTask]);
    setStep('analyse', 'running', 'Combining signals…');

    // Without headers, a no-cors ping at least tells "unreachable" apart from "hidden".
    const headersOk = server.kind === 'done' && server.data.ok;
    let reach: ReachResult = 'not-run';
    if (!headersOk && probe.childFrames === 0) reach = await checkReachable(url, signal);

    const verdict = decide({ requestedUrl: url, testerOrigin: location.origin, embedderOrigin: embedder || undefined, probe: probe as ProbeResult, reach, server });
    setStep('analyse', verdict.status === 'unknown' ? 'warn' : 'pass', `${verdict.confidence.charAt(0).toUpperCase()}${verdict.confidence.slice(1)} confidence`);

    const report: DiagnosticsInput = { url, verdict, server, probe, browser: browserName, embedder, testedAt: new Date() };
    current = { url, report };
    renderVerdict(verdict, report);
    // Embeddable → show the real output straight away: the page rendered in a visible iframe.
    if (verdict.status === 'embeddable') showPreview();
    renderHistory(addHistory({ url, status: verdict.status, at: Date.now() }));
  } catch (error) {
    if (signal.aborted) return;
    statusCard.dataset.state = 'unknown';
    headline.textContent = '⚠ Could Not Determine';
    summary.textContent = `The test failed unexpectedly: ${error instanceof Error ? error.message : String(error)}`;
    setStep('analyse', 'fail', 'Test failed');
  } finally {
    if (!signal.aborted) setBusy(false);
  }
}

// ---------------------------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------------------------

async function copyText(text: string, button: HTMLElement) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.className = 'fixed -left-[9999px]';
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }
  const label = button.querySelector('span:last-child') ?? button;
  const before = label.textContent;
  label.textContent = 'Copied!';
  setTimeout(() => (label.textContent = before), 1600);
}

// ---------------------------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------------------------

form.addEventListener('submit', (event) => {
  event.preventDefault();
  void run(input.value);
});
input.addEventListener('input', () => {
  if (!errorBox.hidden) clearError();
});
input.addEventListener('paste', () => {
  // Pasted links often carry stray spaces or line breaks.
  setTimeout(() => (input.value = input.value.trim()), 0);
});

if (navigator.clipboard && 'readText' in navigator.clipboard) {
  pasteButton.hidden = false;
  pasteButton.addEventListener('click', async () => {
    try {
      const text = (await navigator.clipboard.readText()).trim();
      if (!text) return;
      input.value = text;
      void run(text);
    } catch {
      input.focus();
      showError('Clipboard access was blocked. Press Ctrl+V (or ⌘V) in the box instead.');
    }
  });
}

document.querySelectorAll<HTMLButtonElement>('[data-example]').forEach((button) =>
  button.addEventListener('click', () => {
    input.value = button.dataset.example ?? '';
    void run(input.value);
  }),
);

serverToggle.addEventListener('change', persistSettings);
timeoutSelect.addEventListener('change', persistSettings);
embedderInput.addEventListener('change', persistSettings);

document.addEventListener('click', (event) => {
  const button = (event.target as Element).closest<HTMLElement>('[data-action]');
  if (!button) return;
  switch (button.dataset.action) {
    case 'toggle-preview':
      if (previewCard.hidden) {
        showPreview();
        previewCard.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'nearest' });
      } else hidePreview();
      break;
    case 'reload-preview':
      showPreview();
      break;
    case 'copy-report':
      if (current) void copyText(buildReport(current.report), button);
      break;
    case 'copy-embed':
      if (testedUrl) void copyText(embedSnippet(testedUrl), button);
      break;
    case 'retest':
      if (testedUrl) void run(testedUrl);
      break;
    case 'clear-history':
      clearHistory();
      renderHistory([]);
      break;
  }
});

updateServerNote();
renderHistory();

// Shareable links: ?url=example.com runs a test straight away (also the no-JS form fallback).
const initial = new URLSearchParams(location.search).get('url');
if (initial) {
  input.value = initial;
  void run(initial);
}
