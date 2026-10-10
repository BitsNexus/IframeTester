/**
 * GET /api/check-iframe?url=https://example.com
 *
 * Fetches the page the way a browser iframe would (Sec-Fetch-Dest: iframe), follows redirects
 * one hop at a time so each hop can be vetted, and reports the framing headers of the final
 * response plus a scan of the start of the HTML.
 *
 * Written against the Fetch API only (Request/Response/fetch), so the same handler runs in a
 * Cloudflare Worker (worker/index.ts), in `astro dev` and in `npm run api` (src/server/node.ts).
 */
import { normalizeUrlInput } from '../lib/validate.ts';
import { isBlockedHostname, isPrivateAddress } from '../lib/net-guard.ts';
import { evaluateFraming } from '../lib/policy.ts';
import { scanHtml } from '../lib/html-scan.ts';
import { REPORTED_HEADERS, type CheckFailure, type CheckResponse, type CheckSuccess, type RedirectHop } from '../lib/api-types.ts';

export interface CheckOptions {
  /** Origins allowed to call the API from a browser (CORS). ['*'] allows every origin. */
  allowedOrigins?: string[];
  /** Resolves a hostname to IP addresses so DNS answers pointing at private networks are refused. */
  resolveHost?: (hostname: string) => Promise<string[]>;
  /** Tests only: allow localhost targets. */
  allowPrivateHosts?: boolean;
  /** Whole check, all redirects included. */
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

const MAX_REDIRECTS = 10;
const MAX_HTML_BYTES = 512 * 1024;
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 IframeURLTester/1.0 (+https://bitsnexus.github.io/IframeTester/)';

/** Request headers of a real cross-site iframe navigation, so servers answer as they would to one. */
const IFRAME_REQUEST_HEADERS: Record<string, string> = {
  'user-agent': USER_AGENT,
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'accept-language': 'en-US,en;q=0.9',
  'sec-fetch-dest': 'iframe',
  'sec-fetch-mode': 'navigate',
  'sec-fetch-site': 'cross-site',
  'upgrade-insecure-requests': '1',
};

class CheckError extends Error {
  readonly code: CheckFailure['code'];
  constructor(code: CheckFailure['code'], message: string) {
    super(message);
    this.code = code;
  }
}

function corsHeaders(request: Request, allowed: string[]): Record<string, string> {
  const origin = request.headers.get('origin');
  const headers: Record<string, string> = { vary: 'Origin' };
  if (allowed.includes('*')) headers['access-control-allow-origin'] = '*';
  else if (origin && allowed.includes(origin)) headers['access-control-allow-origin'] = origin;
  return headers;
}

function json(body: CheckResponse, status: number, extra: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...extra,
    },
  });
}

async function assertPublicHost(url: URL, options: CheckOptions): Promise<void> {
  if (options.allowPrivateHosts) return;
  if (url.port && !['80', '443', '8080', '8443'].includes(url.port)) {
    throw new CheckError('blocked-host', `Port ${url.port} is not checked by the server. Only ports 80, 443, 8080 and 8443 are allowed.`);
  }
  if (isBlockedHostname(url.hostname)) {
    throw new CheckError('blocked-host', `${url.hostname} is a local or private address. The server only checks public websites.`);
  }
  if (options.resolveHost && !/^\[|^\d+\.\d+\.\d+\.\d+$/.test(url.hostname)) {
    let addresses: string[];
    try {
      addresses = await options.resolveHost(url.hostname);
    } catch {
      throw new CheckError('dns', `The domain ${url.hostname} could not be found (DNS lookup failed).`);
    }
    if (addresses.some(isPrivateAddress)) {
      throw new CheckError('blocked-host', `${url.hostname} points to a private network address. The server only checks public websites.`);
    }
  }
}

function classifyFetchError(error: unknown, host: string): CheckError {
  if (error instanceof CheckError) return error;
  const err = error as { name?: string; message?: string; cause?: { code?: string; message?: string } };
  const code = err?.cause?.code ?? '';
  const text = `${err?.message ?? ''} ${err?.cause?.message ?? ''}`;
  if (err?.name === 'AbortError' || err?.name === 'TimeoutError' || code === 'UND_ERR_CONNECT_TIMEOUT') {
    return new CheckError('timeout', `${host} took too long to respond.`);
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || /dns|getaddrinfo|name not resolved/i.test(text)) {
    return new CheckError('dns', `The domain ${host} could not be found (DNS lookup failed).`);
  }
  if (/CERT|SSL|TLS|certificate/i.test(code + text)) {
    return new CheckError('tls', `${host} has an invalid or untrusted HTTPS certificate.`);
  }
  if (['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'UND_ERR_SOCKET'].includes(code)) {
    return new CheckError('connect', `Could not connect to ${host} (${code}).`);
  }
  return new CheckError('network', `Could not load ${host}: ${err?.cause?.message ?? err?.message ?? 'network error'}.`);
}

function detectBotProtection(response: Response): string | null {
  const h = response.headers;
  if (h.get('cf-mitigated')) return 'Cloudflare challenge';
  if (response.status === 403 || response.status === 429 || response.status === 503) {
    const server = (h.get('server') ?? '').toLowerCase();
    if (server.includes('cloudflare')) return 'Cloudflare';
    if (server.includes('akamai') || h.has('akamai-grn')) return 'Akamai';
    if (h.has('x-amzn-waf-action') || server.includes('awselb')) return 'AWS WAF';
    if (h.has('x-sucuri-id')) return 'Sucuri';
    if (h.has('x-datadome') || h.has('x-dd-b')) return 'DataDome';
    if (response.status === 429) return 'Rate limiting';
  }
  return null;
}

/** Reads at most MAX_HTML_BYTES of an HTML body, then abandons the rest of the download. */
async function readHtmlStart(response: Response): Promise<{ text: string; bytes: number } | null> {
  const type = (response.headers.get('content-type') ?? 'text/html').toLowerCase();
  if (!response.body || !/html|xml/.test(type)) {
    await response.body?.cancel().catch(() => {});
    return null;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (bytes < MAX_HTML_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      bytes += value.byteLength;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  const buffer = new Uint8Array(Math.min(bytes, MAX_HTML_BYTES));
  let offset = 0;
  for (const chunk of chunks) {
    const slice = chunk.subarray(0, buffer.length - offset);
    buffer.set(slice, offset);
    offset += slice.byteLength;
    if (offset >= buffer.length) break;
  }
  const charset = type.match(/charset=([\w-]+)/)?.[1] ?? 'utf-8';
  let decoder: TextDecoder;
  try {
    decoder = new TextDecoder(charset);
  } catch {
    decoder = new TextDecoder('utf-8');
  }
  return { text: decoder.decode(buffer), bytes: buffer.length };
}

export async function checkUrl(rawUrl: string, options: CheckOptions = {}): Promise<CheckResponse> {
  const started = Date.now();
  const validation = normalizeUrlInput(rawUrl);
  if (!validation.ok) return { ok: false, code: 'invalid-url', error: validation.error };
  const requestedUrl = validation.url;
  const doFetch = options.fetchImpl ?? fetch;
  const signal = AbortSignal.timeout(options.timeoutMs ?? 9000);

  let current = new URL(requestedUrl);
  const redirects: RedirectHop[] = [];
  try {
    for (;;) {
      await assertPublicHost(current, options);
      let response: Response;
      try {
        response = await doFetch(current.href, { method: 'GET', redirect: 'manual', headers: IFRAME_REQUEST_HEADERS, signal });
      } catch (error) {
        throw classifyFetchError(error, current.hostname);
      }

      const location = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && location) {
        await response.body?.cancel().catch(() => {});
        let next: URL;
        try {
          next = new URL(location, current);
        } catch {
          throw new CheckError('network', `${current.hostname} redirected to an invalid address: ${location}`);
        }
        if (next.protocol !== 'http:' && next.protocol !== 'https:') {
          throw new CheckError('network', `${current.hostname} redirected to a ${next.protocol} link, which can’t be shown in a frame.`);
        }
        redirects.push({ url: current.href, status: response.status, location: next.href });
        if (redirects.length > MAX_REDIRECTS) throw new CheckError('too-many-redirects', `More than ${MAX_REDIRECTS} redirects — the page is probably stuck in a redirect loop.`);
        current = next;
        continue;
      }

      const headers: Record<string, string> = {};
      for (const name of REPORTED_HEADERS) {
        const value = response.headers.get(name);
        if (value != null) headers[name] = value;
      }
      const xFrameOptions = response.headers.get('x-frame-options');
      const csp = response.headers.get('content-security-policy');
      const cspReportOnly = response.headers.get('content-security-policy-report-only');
      const botProtection = detectBotProtection(response);

      let html: CheckSuccess['html'] = null;
      try {
        const start = await readHtmlStart(response);
        if (start) html = scanHtml(start.text, start.bytes);
      } catch {
        html = null; // The headers are what matter; a body that fails mid-stream is not fatal.
      }

      const framing = evaluateFraming({ xFrameOptions, csp, cspReportOnly, resourceUrl: current.href });
      return {
        ok: true,
        requestedUrl,
        finalUrl: current.href,
        status: response.status,
        statusText: response.statusText,
        redirects,
        headers,
        xFrameOptions,
        csp,
        cspReportOnly,
        contentType: response.headers.get('content-type'),
        embeddable: framing.allowed,
        botProtection,
        html,
        fetchMs: Date.now() - started,
        checkedAt: new Date().toISOString(),
      };
    }
  } catch (error) {
    const failure = classifyFetchError(error, current.hostname);
    return { ok: false, code: failure.code, error: failure.message, requestedUrl };
  }
}

export async function handleCheckRequest(request: Request, options: CheckOptions = {}): Promise<Response> {
  const cors = corsHeaders(request, options.allowedOrigins ?? ['*']);
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: { ...cors, 'access-control-allow-methods': 'GET, OPTIONS', 'access-control-max-age': '86400' },
    });
  }
  if (request.method !== 'GET') {
    return json({ ok: false, code: 'method-not-allowed', error: 'Use GET /api/check-iframe?url=…' }, 405, { ...cors, allow: 'GET, OPTIONS' });
  }
  const target = new URL(request.url).searchParams.get('url');
  if (!target) {
    return json({ ok: false, code: 'invalid-url', error: 'Add the page to check as ?url=https://example.com' }, 400, cors);
  }
  const result = await checkUrl(target, options);
  // Upstream failures are still a successful *check*: the client shows the reason.
  const status = result.ok || result.code !== 'invalid-url' ? 200 : 400;
  return json(result, status, cors);
}
