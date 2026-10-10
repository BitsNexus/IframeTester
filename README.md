# IFrame URL Tester

Checks whether a web page can be embedded in an `<iframe>`, using real signals rather than guesses. It reads the page's actual
`X-Frame-Options` and `Content-Security-Policy: frame-ancestors` headers, applies the same rules browsers use, and loads the page in a live
iframe. Every answer comes with a confidence level.

Astro 7 + Tailwind 4 static site (LimeWire-style design shared with the BitsNexus Video Tester), plus a small header-check API that runs as a
Cloudflare Worker. Target: `https://bitsnexus.github.io/IframeTester/`.

## Commands

| Command | What it does |
| --- | --- |
| `npm run dev` | Dev server. It also serves the API at `/IframeTester/api/check-iframe/`, so everything works locally. |
| `npm test` | 45 `node:test` cases: policy rules, URL validation, SSRF guard, verdicts, and the API against a local fixture server |
| `npm run lint` | `astro check` plus a type-check of the Worker |
| `npm run build` / `npm run preview` | Static build in `dist/` |
| `npm run api` | Standalone API on `http://localhost:8787/api/check-iframe` (for `preview` builds) |
| `npm run worker:build` | Bundles the Worker to `dist-worker/` (sanity check; wrangler bundles it itself) |

To test a production build locally, run `npm run api`, then build with the API URL set and preview:

```bash
PUBLIC_CHECK_API_URL=http://localhost:8787/api/check-iframe npm run build && npm run preview
```

## How detection works

| Signal | Where | Weight |
| --- | --- | --- |
| `X-Frame-Options` and `CSP frame-ancestors` from the final response (after redirects), fetched with `Sec-Fetch-Dest: iframe` | server (`src/server/check.ts`) | Decides the verdict; high confidence |
| Rules: HTML Standard XFO processing (conflicting values block, ALLOW-FROM ignored) and CSP3 source matching (`'self'`, wildcards, schemes, ports); `frame-ancestors` overrides XFO; report-only never blocks | `src/lib/policy.ts` | – |
| Mixed content (https page cannot frame an http page) | browser | Certain |
| Live hidden iframe: `load` event (a timing only, since browsers fire it for blocked pages too), 10 s timeout, and `contentWindow.length > 0` (a blocked error page never has sub-frames, so frames prove a page rendered) | `src/scripts/probe.ts` | Supporting |
| Bot-protection responses (Cloudflare challenge, WAF 403/429) | server | Headers untrusted → lower confidence |
| Inline frame-busting code, `<meta>` XFO/CSP (which browsers ignore), meta refresh, `Content-Disposition: attachment` | server HTML scan | Caveats |
| no-cors reachability ping (only when headers are unavailable) | browser | Explains failures |

`src/lib/verdict.ts` combines these into **Embeddable / Embedding Blocked / Could Not Determine** with **high / medium / low** confidence.

## Deploy

### 1. The header-check API (Cloudflare Worker, free plan)

```bash
npx wrangler login
npx wrangler deploy
```

This prints a URL such as `https://iframe-url-tester-api.<you>.workers.dev`. The endpoint is that URL plus `/api/check-iframe`. `ALLOWED_ORIGINS`
in `wrangler.toml` limits which sites may call it from a browser (CORS).

The API refuses localhost, private, link-local and metadata addresses (including DNS answers that point there under Node), and only allows
ports 80, 443, 8080 and 8443. It re-checks every redirect hop, reads at most 512 KB of HTML and never stores the URLs it checks.

### 2. The site (GitHub Pages)

1. Push to the `BitsNexus/IframeTester` repository. In **Settings → Pages**, set the source to **GitHub Actions**.
2. Add the repository variable `PUBLIC_CHECK_API_URL` with the Worker endpoint from step 1.
3. Push to `main`. `.github/workflows/deploy.yml` builds and publishes the site.

Without the variable, the site still works in browser-only mode, but most answers will be "Could Not Determine", because browsers deliberately
hide whether a cross-origin frame was blocked.
