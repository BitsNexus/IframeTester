/** The JSON contract of GET /api/check-iframe?url=… — shared by the server handler and the UI. */

export interface HtmlScan {
  /** Bytes of HTML that were scanned (the start of the document only). */
  bytes: number;
  title: string | null;
  /** <meta http-equiv="Content-Security-Policy"> — browsers ignore frame-ancestors in it. */
  metaCsp: string | null;
  /** <meta http-equiv="X-Frame-Options"> — browsers ignore it completely. */
  metaXfo: string | null;
  /** <meta http-equiv="refresh"> target, if any. */
  metaRefresh: string | null;
  /** Inline code that navigates the top window or hides the page when framed. */
  frameBusting: string[];
  /** Inline code that only checks whether the page is framed. */
  frameDetection: string[];
}

export interface RedirectHop {
  url: string;
  status: number;
  location: string;
}

export interface CheckSuccess {
  ok: true;
  requestedUrl: string;
  finalUrl: string;
  status: number;
  statusText: string;
  redirects: RedirectHop[];
  /** Framing-related response headers of the final response (lower-case names). */
  headers: Record<string, string>;
  xFrameOptions: string | null;
  csp: string | null;
  cspReportOnly: string | null;
  contentType: string | null;
  /** Whether an unrelated third-party site may frame the page, judged from the headers alone. */
  embeddable: boolean;
  /** A bot-protection / WAF response was detected, so browsers may get different headers. */
  botProtection: string | null;
  html: HtmlScan | null;
  fetchMs: number;
  checkedAt: string;
}

export type CheckErrorCode =
  | 'invalid-url'
  | 'blocked-host'
  | 'dns'
  | 'connect'
  | 'tls'
  | 'timeout'
  | 'too-many-redirects'
  | 'network'
  | 'method-not-allowed';

export interface CheckFailure {
  ok: false;
  code: CheckErrorCode;
  error: string;
  requestedUrl?: string;
}

export type CheckResponse = CheckSuccess | CheckFailure;

/** Headers the API reports back. Everything else is dropped. */
export const REPORTED_HEADERS = [
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
  'content-type',
  'content-disposition',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'server',
  'cf-mitigated',
] as const;
