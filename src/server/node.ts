/**
 * Node adapter for the header-check handler: a connect-style middleware used by `astro dev`
 * (see astro.config.mjs) and by the standalone `npm run api` server (serve.ts).
 * Adds a DNS lookup so hostnames that resolve to private addresses are refused.
 */
import { lookup } from 'node:dns/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { handleCheckRequest, type CheckOptions } from './check.ts';

export const API_PATH = '/api/check-iframe';

export const resolveHost = async (hostname: string) => (await lookup(hostname, { all: true, verbatim: true })).map((a) => a.address);

/** Matches /api/check-iframe with or without a base path and trailing slash. */
export const isApiPath = (pathname: string) => /(?:^|\/)api\/check-iframe\/?$/.test(pathname);

export function createApiMiddleware(options: CheckOptions = {}) {
  return async (req: IncomingMessage, res: ServerResponse, next: () => void) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    if (!isApiPath(url.pathname)) return next();
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (typeof value === 'string') headers.set(name, value);
    }
    const response = await handleCheckRequest(new Request(url, { method: req.method, headers }), { resolveHost, ...options });
    res.statusCode = response.status;
    response.headers.forEach((value, name) => res.setHeader(name, value));
    res.end(await response.text());
  };
}
