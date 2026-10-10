/**
 * Cloudflare Worker that hosts the header-check API in production:
 *   https://<worker>.workers.dev/api/check-iframe?url=https://example.com
 *
 * GitHub Pages can only serve static files, so the site calls this Worker (PUBLIC_CHECK_API_URL).
 * Workers can't reach private networks, and the handler also refuses private/local hostnames.
 * Deploy: see README.md → "Deploy the header-check API".
 */
import { handleCheckRequest } from '../src/server/check.ts';

interface Env {
  /** Comma-separated origins allowed to call the API from a browser, e.g. "https://bitsnexus.github.io". */
  ALLOWED_ORIGINS?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname !== '/api/check-iframe' && pathname !== '/api/check-iframe/') {
      return new Response('Not found. Use /api/check-iframe?url=https://example.com', { status: 404 });
    }
    const allowedOrigins = (env.ALLOWED_ORIGINS ?? '*').split(',').map((s) => s.trim()).filter(Boolean);
    return handleCheckRequest(request, { allowedOrigins });
  },
} satisfies ExportedHandler<Env>;
