/**
 * Decides whether a response may be shown inside a frame, using the same rules browsers apply:
 *
 *  - CSP Level 3 `frame-ancestors` (https://w3c.github.io/webappsec-csp/#directive-frame-ancestors),
 *    including source-expression matching ("Does url match expression in origin").
 *  - The HTML Standard's X-Frame-Options processing
 *    (https://html.spec.whatwg.org/multipage/document-lifecycle.html#the-x-frame-options-header):
 *    XFO is ignored whenever an enforced CSP has a frame-ancestors directive; conflicting values
 *    block; ALLOW-FROM and unknown values are ignored by every current browser.
 *
 * Pure functions — shared by the browser UI, the header-check API and the tests.
 */

export type Directives = Record<string, string[]>;

export interface CspPolicy {
  raw: string;
  disposition: 'enforce' | 'report';
  directives: Directives;
}

/** An unrelated HTTPS site, used to answer "can *any other* site embed this?". */
export const THIRD_PARTY_ORIGIN = 'https://third-party-site.invalid';

// ---------------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------------

/**
 * Parses a Content-Security-Policy header value. Several headers arrive joined with commas,
 * and each comma-separated part is a separate policy that must be satisfied on its own.
 */
export function parseCsp(header: string | null | undefined, disposition: CspPolicy['disposition'] = 'enforce'): CspPolicy[] {
  if (!header) return [];
  return header
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
    .map((raw) => ({ raw, disposition, directives: parseSerializedPolicy(raw) }));
}

function parseSerializedPolicy(serialized: string): Directives {
  const directives: Directives = {};
  for (const token of serialized.split(';')) {
    const trimmed = token.trim();
    if (!trimmed) continue;
    const [name = '', ...values] = trimmed.split(/[\t\n\f\r ]+/);
    const directive = name.toLowerCase();
    if (!/^[a-z0-9-]+$/.test(directive)) continue;
    // Duplicate directives are ignored; the first one wins.
    if (Object.hasOwn(directives, directive)) continue;
    directives[directive] = values;
  }
  return directives;
}

/** "get, decode, and split" X-Frame-Options, lower-cased and de-duplicated. */
export function parseXfo(header: string | null | undefined): string[] {
  if (header == null) return [];
  const values = header.split(',').map((v) => v.trim().toLowerCase());
  return [...new Set(values)];
}

// ---------------------------------------------------------------------------------------------
// CSP source matching (CSP3 §6.7.2)
// ---------------------------------------------------------------------------------------------

const DEFAULT_PORTS: Record<string, string> = { 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443', 'ftp:': '21' };

const SCHEME_SOURCE = /^([a-z][a-z0-9+.-]*):$/i;
const HOST_SOURCE = /^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*|(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?|\[[0-9a-f:.]+\])(?::(\*|\d+))?(\/[^\s;,]*)?$/i;

/** Scheme-part match: 'http' also matches 'https' (and ws → wss) so upgraded sites keep working. */
function schemeMatches(expression: string, scheme: string): boolean {
  const a = expression.toLowerCase().replace(/:$/, '');
  const b = scheme.toLowerCase().replace(/:$/, '');
  if (a === b) return true;
  if (a === 'http') return b === 'https';
  if (a === 'ws') return b === 'wss' || b === 'http' || b === 'https';
  if (a === 'wss') return b === 'https';
  return false;
}

function hostMatches(pattern: string, host: string): boolean {
  const p = pattern.toLowerCase().replace(/\.$/, '');
  const h = host.toLowerCase().replace(/\.$/, '');
  if (p === '*') return true;
  if (p.startsWith('*.')) return h.endsWith(p.slice(1));
  return p === h;
}

function portMatches(port: string | undefined, url: URL): boolean {
  const urlPort = url.port || DEFAULT_PORTS[url.protocol];
  if (!port) return urlPort === DEFAULT_PORTS[url.protocol];
  if (port === '*') return true;
  return String(Number(port)) === urlPort;
}

function pathMatches(expressionPath: string | undefined, url: URL): boolean {
  if (!expressionPath) return true;
  const path = url.pathname || '/';
  if (expressionPath === '/' && path === '/') return true;
  const exact = !expressionPath.endsWith('/');
  const a = expressionPath.split('/');
  const b = path.split('/');
  if (a.length > b.length) return false;
  if (exact && a.length !== b.length) return false;
  if (!exact) a.pop();
  const decode = (s: string) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  };
  return a.every((segment, i) => decode(segment) === decode(b[i] ?? ''));
}

/** Does `url` (an ancestor's origin) match one source expression, for a resource at `resource`? */
export function sourceMatches(expression: string, url: URL, resource: URL): boolean {
  const expr = expression.trim();
  if (expr === '*') {
    return url.protocol === 'http:' || url.protocol === 'https:' || url.protocol === resource.protocol;
  }

  const scheme = expr.match(SCHEME_SOURCE);
  if (scheme) return schemeMatches(scheme[1]!, url.protocol);

  const host = expr.match(HOST_SOURCE);
  if (host && !expr.startsWith("'")) {
    const [, exprScheme, exprHost, exprPort, exprPath] = host;
    if (exprScheme) {
      if (!schemeMatches(exprScheme, url.protocol)) return false;
    } else if (!schemeMatches(resource.protocol, url.protocol)) {
      return false;
    }
    if (!url.hostname) return false;
    return hostMatches(exprHost!, url.hostname) && portMatches(exprPort, url) && pathMatches(exprPath, url);
  }

  if (expr.toLowerCase() === "'self'") {
    if (url.origin === resource.origin) return true;
    const samePorts =
      (url.port || DEFAULT_PORTS[url.protocol]) === (resource.port || DEFAULT_PORTS[resource.protocol]) ||
      (!url.port && !resource.port);
    return (
      url.hostname === resource.hostname &&
      samePorts &&
      (url.protocol === 'https:' || url.protocol === 'wss:' || (resource.protocol === 'http:' && url.protocol === 'http:'))
    );
  }

  // 'none', 'unsafe-inline', nonces, hashes, typos… match nothing in frame-ancestors.
  return false;
}

/** Does the ancestor origin match a whole frame-ancestors source list? */
export function sourceListMatches(list: string[], ancestorOrigin: string, resourceUrl: string): boolean {
  if (list.length === 0) return false;
  if (list.length === 1 && list[0]!.toLowerCase() === "'none'") return false;
  const url = new URL(ancestorOrigin);
  const resource = new URL(resourceUrl);
  return list.some((expression) => sourceMatches(expression, url, resource));
}

// ---------------------------------------------------------------------------------------------
// X-Frame-Options (HTML Standard)
// ---------------------------------------------------------------------------------------------

export type XfoKind = 'absent' | 'deny' | 'sameorigin' | 'conflict' | 'allow-from' | 'allowall' | 'unrecognised';

export function classifyXfo(values: string[]): XfoKind {
  if (values.length === 0) return 'absent';
  const known = values.filter((v) => v === 'deny' || v === 'sameorigin' || v === 'allowall');
  if (values.length > 1) return known.length > 0 ? 'conflict' : 'unrecognised';
  const [only = ''] = values;
  if (only === 'deny' || only === 'sameorigin' || only === 'allowall') return only;
  if (only.startsWith('allow-from')) return 'allow-from';
  return only === '' ? 'absent' : 'unrecognised';
}

export function xfoAllows(kind: XfoKind, ancestorOrigin: string, resourceUrl: string): boolean {
  if (kind === 'deny' || kind === 'conflict') return false;
  if (kind === 'sameorigin') return new URL(ancestorOrigin).origin === new URL(resourceUrl).origin;
  return true;
}

// ---------------------------------------------------------------------------------------------
// Combined decision
// ---------------------------------------------------------------------------------------------

export type Audience =
  | { kind: 'anyone' }
  | { kind: 'nobody' }
  | { kind: 'same-origin'; origin: string }
  | { kind: 'listed'; sources: string[] };

export interface FrameAncestorsEntry {
  sources: string[];
  allows: boolean;
  audience: Audience;
}

export interface FramingInput {
  xFrameOptions: string | null;
  csp: string | null;
  cspReportOnly?: string | null;
  /** The URL whose response carried the headers (the final URL after redirects). */
  resourceUrl: string;
  /** Origin of the page that wants to embed it. Defaults to an unrelated third-party site. */
  embedderOrigin?: string;
}

export interface FramingResult {
  allowed: boolean;
  /** Which header made the decision. CSP frame-ancestors beats X-Frame-Options when both exist. */
  decidedBy: 'csp' | 'xfo' | 'none';
  embedderOrigin: string;
  audience: Audience;
  csp: { enforced: FrameAncestorsEntry[]; reportOnly: FrameAncestorsEntry[]; policyCount: number };
  xfo: { raw: string | null; values: string[]; kind: XfoKind; allows: boolean; ignored: boolean };
}

function audienceForList(list: string[], resourceUrl: string): Audience {
  const origin = new URL(resourceUrl).origin;
  if (!sourceListMatches(list, origin, resourceUrl) && !sourceListMatches(list, THIRD_PARTY_ORIGIN, resourceUrl)) {
    // Neither the site itself nor a random site: either nobody, or only the listed hosts.
    const meaningful = list.filter((s) => !/^'(?:none|self)'$/i.test(s) && (SCHEME_SOURCE.test(s) || HOST_SOURCE.test(s) || s === '*'));
    return meaningful.length ? { kind: 'listed', sources: meaningful } : { kind: 'nobody' };
  }
  if (sourceListMatches(list, THIRD_PARTY_ORIGIN, resourceUrl)) return { kind: 'anyone' };
  const others = list.filter((s) => s.toLowerCase() !== "'self'" && s.toLowerCase() !== "'none'");
  return others.length ? { kind: 'listed', sources: ["'self'", ...others] } : { kind: 'same-origin', origin };
}

function intersectAudiences(audiences: Audience[]): Audience {
  if (audiences.some((a) => a.kind === 'nobody')) return { kind: 'nobody' };
  const restricted = audiences.filter((a) => a.kind !== 'anyone');
  if (restricted.length === 0) return { kind: 'anyone' };
  if (restricted.length === 1) return restricted[0]!;
  const sameOrigin = restricted.find((a) => a.kind === 'same-origin');
  if (sameOrigin) return sameOrigin;
  return { kind: 'listed', sources: [...new Set(restricted.flatMap((a) => (a.kind === 'listed' ? a.sources : [])))] };
}

export function evaluateFraming(input: FramingInput): FramingResult {
  const embedderOrigin = input.embedderOrigin ? new URL(input.embedderOrigin).origin : THIRD_PARTY_ORIGIN;
  const { resourceUrl } = input;

  const entries = (policies: CspPolicy[]): FrameAncestorsEntry[] =>
    policies
      .filter((p) => Object.hasOwn(p.directives, 'frame-ancestors'))
      .map((p) => {
        const sources = p.directives['frame-ancestors']!;
        return { sources, allows: sourceListMatches(sources, embedderOrigin, resourceUrl), audience: audienceForList(sources, resourceUrl) };
      });

  const enforcedPolicies = parseCsp(input.csp, 'enforce');
  const enforced = entries(enforcedPolicies);
  const reportOnly = entries(parseCsp(input.cspReportOnly, 'report'));

  const values = parseXfo(input.xFrameOptions);
  const kind = classifyXfo(values);
  const xfoAllowsIt = xfoAllows(kind, embedderOrigin, resourceUrl);
  const cspDecides = enforced.length > 0;

  let allowed: boolean;
  let decidedBy: FramingResult['decidedBy'];
  let audience: Audience;
  if (cspDecides) {
    allowed = enforced.every((e) => e.allows);
    decidedBy = 'csp';
    audience = intersectAudiences(enforced.map((e) => e.audience));
  } else if (kind === 'deny' || kind === 'conflict' || kind === 'sameorigin') {
    allowed = xfoAllowsIt;
    decidedBy = 'xfo';
    audience = kind === 'sameorigin' ? { kind: 'same-origin', origin: new URL(resourceUrl).origin } : { kind: 'nobody' };
  } else {
    allowed = true;
    decidedBy = 'none';
    audience = { kind: 'anyone' };
  }

  return {
    allowed,
    decidedBy,
    embedderOrigin,
    audience,
    csp: { enforced, reportOnly, policyCount: enforcedPolicies.length },
    xfo: { raw: input.xFrameOptions, values, kind, allows: xfoAllowsIt, ignored: cspDecides && kind !== 'absent' },
  };
}

/** "frame-ancestors 'self' https://a.com" → "'self' https://a.com" for display. */
export const formatSources = (sources: string[]) => (sources.length ? sources.join(' ') : '(empty — blocks everyone)');
