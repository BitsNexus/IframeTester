/**
 * `npm run api` — the header-check API on http://localhost:8787/api/check-iframe, for use with
 * `astro preview` (set PUBLIC_CHECK_API_URL=http://localhost:8787/api/check-iframe before building).
 * `astro dev` doesn't need this: it serves the same API itself.
 */
import { createServer } from 'node:http';
import { createApiMiddleware, API_PATH } from './node.ts';

const port = Number(process.env.PORT ?? 8787);
const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? '*').split(',').map((s) => s.trim());
const middleware = createApiMiddleware({ allowedOrigins });

createServer((req, res) => {
  middleware(req, res, () => {
    res.statusCode = 404;
    res.setHeader('content-type', 'text/plain');
    res.end(`Not found. Try ${API_PATH}?url=https://example.com`);
  }).catch((error: unknown) => {
    res.statusCode = 500;
    res.end(String(error));
  });
}).listen(port, () => {
  console.log(`Iframe check API → http://localhost:${port}${API_PATH}?url=https://example.com`);
});
