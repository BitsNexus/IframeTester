/**
 * Browser client for the header-check API.
 *  - Production: PUBLIC_CHECK_API_URL (the Cloudflare Worker, see README). Empty → browser-only mode.
 *  - `astro dev`: the dev server answers at <base>/api/check-iframe/ itself.
 */
import type { CheckResponse } from './api-types.ts';

const configured = (import.meta.env.PUBLIC_CHECK_API_URL ?? '').trim();
const devDefault = import.meta.env.DEV ? `${import.meta.env.BASE_URL.replace(/\/+$/, '')}/api/check-iframe/` : '';

export const CHECK_API_URL: string = configured || devDefault;
export const hasCheckApi = CHECK_API_URL !== '';

export async function checkHeaders(url: string, signal: AbortSignal): Promise<CheckResponse> {
  const endpoint = new URL(CHECK_API_URL, location.href);
  endpoint.searchParams.set('url', url);
  const response = await fetch(endpoint, { signal, credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!response.headers.get('content-type')?.includes('json')) {
    throw new Error(`The header-check API answered with HTTP ${response.status}.`);
  }
  return (await response.json()) as CheckResponse;
}
