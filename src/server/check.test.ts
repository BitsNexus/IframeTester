import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { checkUrl, handleCheckRequest } from './check.ts';
import { scanHtml } from '../lib/html-scan.ts';
import type { CheckSuccess } from '../lib/api-types.ts';

let server: Server;
let base = '';
const seen: Record<string, string | undefined>[] = [];

const routes: Record<string, (res: import('node:http').ServerResponse) => void> = {
  '/open': (res) => {
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end('<!doctype html><title>Open &amp; friendly</title><h1>hi</h1>');
  },
  '/deny': (res) => {
    res.setHeader('x-frame-options', 'DENY');
    res.end('<p>no</p>');
  },
  '/csp-none': (res) => {
    res.setHeader('content-security-policy', "default-src 'self'; frame-ancestors 'none'");
    res.end('<p>no</p>');
  },
  '/csp-overrides': (res) => {
    res.setHeader('x-frame-options', 'SAMEORIGIN');
    res.setHeader('content-security-policy', 'frame-ancestors *');
    res.end('<p>yes</p>');
  },
  '/redirect': (res) => {
    res.statusCode = 302;
    res.setHeader('location', '/redirect-2');
    res.end();
  },
  '/redirect-2': (res) => {
    res.statusCode = 301;
    res.setHeader('location', `${base}/deny`);
    res.end();
  },
  '/loop': (res) => {
    res.statusCode = 302;
    res.setHeader('location', '/loop');
    res.end();
  },
  '/challenge': (res) => {
    res.statusCode = 403;
    res.setHeader('server', 'cloudflare');
    res.setHeader('cf-mitigated', 'challenge');
    res.setHeader('x-frame-options', 'SAMEORIGIN');
    res.end('<title>Just a moment...</title>');
  },
  '/buster': (res) => {
    res.setHeader('content-type', 'text/html');
    res.end(`<html><head><meta http-equiv="X-Frame-Options" content="deny"><meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">
      <style id="antiClickjack">body{display:none !important;}</style>
      <script>if (self === top) { document.getElementById('antiClickjack').remove(); } else { top.location = self.location; }</script></head></html>`);
  },
  '/slow': () => {
    /* never answers */
  },
  '/file': (res) => {
    res.setHeader('content-type', 'application/pdf');
    res.setHeader('content-disposition', 'attachment; filename="a.pdf"');
    res.end('%PDF-1.7');
  },
};

before(async () => {
  server = createServer((req, res) => {
    seen.push({ path: req.url, dest: req.headers['sec-fetch-dest'] as string | undefined, ua: req.headers['user-agent'] });
    (routes[req.url ?? ''] ?? ((r) => ((r.statusCode = 404), r.end('missing'))))(res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => {
  server.closeAllConnections();
  server.close();
});

const check = async (path: string, timeoutMs?: number) => checkUrl(`${base}${path}`, { allowPrivateHosts: true, timeoutMs }) as Promise<CheckSuccess>;

test('an open page is embeddable and sends iframe fetch metadata', async () => {
  const r = await check('/open');
  assert.equal(r.ok, true);
  assert.equal(r.status, 200);
  assert.equal(r.embeddable, true);
  assert.equal(r.xFrameOptions, null);
  assert.equal(r.html?.title, 'Open & friendly');
  const req = seen.find((s) => s.path === '/open');
  assert.equal(req?.dest, 'iframe');
  assert.match(req?.ua ?? '', /IframeURLTester/);
});

test('X-Frame-Options and CSP headers are reported', async () => {
  const deny = await check('/deny');
  assert.equal(deny.embeddable, false);
  assert.equal(deny.xFrameOptions, 'DENY');
  const none = await check('/csp-none');
  assert.equal(none.embeddable, false);
  assert.match(none.csp ?? '', /frame-ancestors 'none'/);
  const override = await check('/csp-overrides');
  assert.equal(override.embeddable, true, 'frame-ancestors * wins over XFO SAMEORIGIN');
});

test('redirects are followed and recorded; headers come from the final page', async () => {
  const r = await check('/redirect');
  assert.equal(r.finalUrl, `${base}/deny`);
  assert.deepEqual(
    r.redirects.map((h) => h.status),
    [302, 301],
  );
  assert.equal(r.embeddable, false);
});

test('redirect loops stop', async () => {
  const r = (await checkUrl(`${base}/loop`, { allowPrivateHosts: true })) as unknown as { ok: false; code: string };
  assert.equal(r.ok, false);
  assert.equal(r.code, 'too-many-redirects');
});

test('bot-protection responses are flagged', async () => {
  const r = await check('/challenge');
  assert.equal(r.botProtection, 'Cloudflare challenge');
  assert.equal(r.status, 403);
});

test('HTML scan finds frame busters and ignored meta tags', async () => {
  const r = await check('/buster');
  assert.equal(r.embeddable, true, 'meta tags do not count');
  assert.equal(r.html?.metaXfo, 'deny');
  assert.equal(r.html?.metaCsp, "frame-ancestors 'none'");
  assert.deepEqual(r.html?.frameBusting, ['top.location assignment', 'anti-clickjacking style']);
});

test('non-HTML downloads are reported without reading the body', async () => {
  const r = await check('/file');
  assert.equal(r.headers['content-disposition'], 'attachment; filename="a.pdf"');
  assert.equal(r.html, null);
});

test('timeouts are reported', async () => {
  const r = (await checkUrl(`${base}/slow`, { allowPrivateHosts: true, timeoutMs: 300 })) as unknown as { code: string };
  assert.equal(r.code, 'timeout');
});

test('private and local targets are refused without allowPrivateHosts', async () => {
  for (const target of [`${base}/open`, 'http://localhost/', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/']) {
    const r = (await checkUrl(target)) as unknown as { ok: boolean; code: string };
    assert.equal(r.ok, false, target);
    assert.equal(r.code, 'blocked-host', target);
  }
  const rebinding = (await checkUrl('https://evil.example.com/', { resolveHost: async () => ['10.0.0.7'] })) as unknown as { code: string };
  assert.equal(rebinding.code, 'blocked-host');
  const oddPort = (await checkUrl('https://example.com:22/')) as unknown as { code: string };
  assert.equal(oddPort.code, 'blocked-host');
});

test('invalid URLs and dangerous schemes are rejected before any request', async () => {
  const r = (await checkUrl('javascript:alert(1)')) as unknown as { code: string };
  assert.equal(r.code, 'invalid-url');
});

test('HTTP handler: CORS, methods and status codes', async () => {
  const opts = { allowPrivateHosts: true, allowedOrigins: ['https://bitsnexus.github.io'] };
  const res = await handleCheckRequest(new Request(`https://api.test/api/check-iframe?url=${encodeURIComponent(`${base}/open`)}`, { headers: { origin: 'https://bitsnexus.github.io' } }), opts);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), 'https://bitsnexus.github.io');
  assert.equal(((await res.json()) as CheckSuccess).embeddable, true);

  const foreign = await handleCheckRequest(new Request('https://api.test/api/check-iframe?url=example.com', { method: 'OPTIONS', headers: { origin: 'https://evil.test' } }), opts);
  assert.equal(foreign.headers.get('access-control-allow-origin'), null);

  const missing = await handleCheckRequest(new Request('https://api.test/api/check-iframe'), opts);
  assert.equal(missing.status, 400);
  const post = await handleCheckRequest(new Request('https://api.test/api/check-iframe', { method: 'POST' }), opts);
  assert.equal(post.status, 405);
});

test('scanHtml ignores harmless code', () => {
  const s = scanHtml('<script>var a = top === self; console.log(window.location.href = "/x")</script>');
  assert.deepEqual(s.frameBusting, []);
  assert.deepEqual(s.frameDetection, []);
  const detect = scanHtml('<script>if (window.top !== window.self) track("framed")</script>');
  assert.deepEqual(detect.frameDetection, ['top !== self check']);
  assert.equal(scanHtml('<meta http-equiv="refresh" content="0; url=https://x.com/next">').metaRefresh, 'https://x.com/next');
});
