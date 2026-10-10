// @ts-check
import { defineConfig, fontProviders } from 'astro/config';
import { loadEnv } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';
import { createApiMiddleware } from './src/server/node.ts';

// .env files are not loaded into process.env for the config file, so read them explicitly.
const env = loadEnv(process.env.NODE_ENV ?? 'production', process.cwd(), '');

// Deployed as a GitHub Pages *project* site: https://bitsnexus.github.io/IframeTester/
const site = env.PUBLIC_SITE_URL || 'https://bitsnexus.github.io';
const base = env.PUBLIC_BASE_PATH || '/IframeTester';

/** `astro dev` serves the header-check API itself at <base>/api/check-iframe (see src/server). */
const devApi = {
  name: 'dev-check-iframe-api',
  hooks: {
    /** @param {{ server: import('vite').ViteDevServer }} options */
    'astro:server:setup': ({ server }) => {
      server.middlewares.use(createApiMiddleware({ allowedOrigins: ['*'] }));
    },
  },
};

export default defineConfig({
  site,
  base,
  trailingSlash: 'always',
  compressHTML: true,

  // GitHub Pages can't send headers, so Astro emits the CSP as a <meta> tag with hashes for every
  // script and style it renders. The tester must be able to frame any http(s) page (frame-src)
  // and call the header-check API plus a no-cors reachability ping (connect-src).
  security: {
    csp: {
      directives: [
        "default-src 'self'",
        'frame-src http: https:',
        "connect-src 'self' https: http:",
        "img-src 'self' data:",
        "font-src 'self'",
        "worker-src 'none'",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'",
      ],
    },
  },

  integrations: [sitemap({ filter: (page) => !/\/404\/?$/.test(page) }), devApi],

  fonts: [
    {
      provider: fontProviders.google(),
      name: 'DM Sans',
      cssVariable: '--font-dm-sans',
      weights: ['400 700'],
      styles: ['normal'],
      subsets: ['latin'],
      fallbacks: ['ui-sans-serif', 'system-ui', 'sans-serif'],
    },
  ],

  vite: {
    plugins: [tailwindcss()],
  },
});
