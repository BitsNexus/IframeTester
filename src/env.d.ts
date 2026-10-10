interface ImportMetaEnv {
  /** Header-check API endpoint, e.g. https://iframe-url-tester-api.<you>.workers.dev/api/check-iframe. Empty → browser-only mode. */
  readonly PUBLIC_CHECK_API_URL?: string;
  readonly PUBLIC_SITE_URL?: string;
  readonly PUBLIC_BASE_PATH?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
