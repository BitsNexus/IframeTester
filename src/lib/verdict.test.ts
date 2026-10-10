import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, type ProbeResult, type ServerOutcome, type VerdictInput } from './verdict.ts';
import type { CheckSuccess } from './api-types.ts';

const loaded: ProbeResult = { outcome: 'load', loadMs: 800, childFrames: 0, timeoutMs: 10000 };
const rendered: ProbeResult = { ...loaded, childFrames: 2 };
const timedOut: ProbeResult = { outcome: 'timeout', loadMs: null, childFrames: 0, timeoutMs: 10000 };

const page = (over: Partial<CheckSuccess> = {}): ServerOutcome => ({
  kind: 'done',
  data: {
    ok: true,
    requestedUrl: 'https://site.com/',
    finalUrl: 'https://site.com/',
    status: 200,
    statusText: 'OK',
    redirects: [],
    headers: {},
    xFrameOptions: null,
    csp: null,
    cspReportOnly: null,
    contentType: 'text/html',
    embeddable: true,
    botProtection: null,
    html: null,
    fetchMs: 100,
    checkedAt: '',
    ...over,
  },
});

const run = (over: Partial<VerdictInput>) =>
  decide({ requestedUrl: 'https://site.com/', testerOrigin: 'https://bitsnexus.github.io', probe: loaded, reach: 'not-run', server: page(), ...over });

test('open page + load → embeddable, high confidence', () => {
  const v = run({});
  assert.equal(v.status, 'embeddable');
  assert.equal(v.confidence, 'high');
});

test('XFO DENY → blocked, high confidence, even though load fired', () => {
  const v = run({ server: page({ xFrameOptions: 'DENY' }) });
  assert.equal(v.status, 'blocked');
  assert.equal(v.confidence, 'high');
  assert.ok(v.reasons.some((r) => r.includes('X-Frame-Options: DENY')));
});

test("frame-ancestors 'none' → blocked", () => {
  const v = run({ server: page({ csp: "frame-ancestors 'none'" }) });
  assert.equal(v.status, 'blocked');
  assert.ok(v.reasons.some((r) => r.includes("frame-ancestors 'none'")));
});

test('allow-list: blocked for others, allowed for a listed embedder', () => {
  const server = page({ csp: 'frame-ancestors https://partner.com' });
  assert.equal(run({ server }).status, 'blocked');
  const v = run({ server, embedderOrigin: 'https://partner.com' });
  assert.equal(v.status, 'embeddable');
  assert.match(v.summary, /Other websites are blocked/);
});

test('without headers, a plain load is inconclusive', () => {
  const v = run({ server: { kind: 'disabled' } });
  assert.equal(v.status, 'unknown');
  assert.equal(v.confidence, 'low');
});

test('without headers, rendered sub-frames prove the page displayed', () => {
  const v = run({ server: { kind: 'not-configured' }, probe: rendered });
  assert.equal(v.status, 'embeddable');
  assert.equal(v.confidence, 'medium');
});

test('timeout without headers → request timed out', () => {
  const v = run({ server: { kind: 'unavailable', error: 'offline' }, probe: timedOut });
  assert.equal(v.headline, 'Request Timed Out');
  assert.deepEqual(v.reasons, ['Network issue', 'Slow website', 'Embedding restrictions']);
});

test('timeout with permissive headers → embeddable, medium', () => {
  const v = run({ probe: timedOut });
  assert.equal(v.status, 'embeddable');
  assert.equal(v.confidence, 'medium');
});

test('mixed content is blocked on https testers but not on http ones', () => {
  const probe: ProbeResult = { outcome: 'skipped-mixed-content', loadMs: null, childFrames: 0, timeoutMs: 10000 };
  const v = run({ requestedUrl: 'http://site.com/', probe, server: page({ finalUrl: 'https://site.com/' }) });
  assert.equal(v.status, 'blocked');
  assert.ok(v.tips.some((t) => t.includes('https://site.com/')));
  assert.equal(run({ requestedUrl: 'http://site.com/', testerOrigin: 'http://localhost:4370' }).status, 'embeddable');
});

test('bot protection makes the headers untrustworthy', () => {
  const server = page({ status: 403, botProtection: 'Cloudflare challenge', xFrameOptions: 'SAMEORIGIN' });
  assert.equal(run({ server }).status, 'unknown');
  assert.equal(run({ server, probe: rendered }).status, 'embeddable');
});

test('caveats lower confidence', () => {
  assert.equal(run({ server: page({ status: 404, statusText: 'Not Found' }) }).confidence, 'medium');
  const html = { bytes: 1, title: null, metaCsp: null, metaXfo: null, metaRefresh: null, frameBusting: ['top.location assignment'], frameDetection: [] };
  assert.equal(run({ server: page({ html }) }).confidence, 'medium');
});

test('downloads and DNS failures are explained', () => {
  assert.equal(run({ server: page({ headers: { 'content-disposition': 'attachment; filename=a.zip' } }) }).headline, 'Downloads Instead of Displaying');
  const dns = run({ server: { kind: 'done', data: { ok: false, code: 'dns', error: 'The domain x.com could not be found.' } } });
  assert.equal(dns.headline, 'Site Not Found');
  assert.equal(dns.status, 'unknown');
});
