import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeUrlInput } from './validate.ts';
import { isBlockedHostname, isPrivateAddress } from './net-guard.ts';

const ok = (input: string) => {
  const r = normalizeUrlInput(input);
  assert.ok(r.ok, `${input} should be valid: ${!r.ok ? r.error : ''}`);
  return r.url;
};
const bad = (input: string) => {
  const r = normalizeUrlInput(input);
  assert.equal(r.ok, false, `${input} should be rejected`);
  return r.ok ? '' : r.error;
};

test('adds https:// when missing', () => {
  assert.equal(ok('example.com'), 'https://example.com/');
  assert.equal(ok('sub.domain.com/page?x=1#top'), 'https://sub.domain.com/page?x=1#top');
  assert.equal(ok('//example.com/a'), 'https://example.com/a');
  assert.equal(ok('example.com:8080/path'), 'https://example.com:8080/path');
  assert.equal(ok('localhost:4321'), 'https://localhost:4321/');
  const added = normalizeUrlInput('example.com');
  assert.equal(added.ok && added.note, 'Added https://');
});

test('keeps http and https URLs', () => {
  assert.equal(ok('https://example.com'), 'https://example.com/');
  assert.equal(ok('HTTP://Example.COM/Path'), 'http://example.com/Path');
  assert.equal(ok('https://xn--bcher-kva.example/'), 'https://xn--bcher-kva.example/');
  assert.equal(ok('https://bücher.de'), 'https://xn--bcher-kva.de/');
  assert.equal(ok('http://93.184.215.14/'), 'http://93.184.215.14/');
});

test('cleans pasted wrappers', () => {
  assert.equal(ok('  <https://example.com>  '), 'https://example.com/');
  assert.equal(ok('"https://example.com/page".'), 'https://example.com/page');
});

test('rejects dangerous and unsupported protocols', () => {
  assert.match(bad('javascript:alert(1)'), /not allowed/);
  assert.match(bad('JavaScript:alert(1)'), /not allowed/);
  assert.match(bad('java\tscript:alert(1)'), /not allowed/);
  assert.match(bad('data:text/html,<b>x</b>'), /not allowed/);
  assert.match(bad('file:///C:/secret.txt'), /not allowed/);
  assert.match(bad('ftp://example.com'), /http/);
  assert.match(bad('mailto:me@example.com'), /http/);
});

test('rejects malformed input', () => {
  bad('');
  bad('   ');
  bad('exa mple.com');
  bad('example');
  bad('example.');
  bad('example.c0m');
  bad('https://');
  bad('https://user:pass@example.com');
  bad(`https://example.com/${'a'.repeat(2100)}`);
});

test('SSRF guard blocks private and local hosts', () => {
  for (const host of ['localhost', 'app.localhost', 'printer.local', 'db.internal', '127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '[::1]', '[fd00::1]', '[fe80::1]', '[::ffff:127.0.0.1]', '[::ffff:a00:1]', 'metadata.google.internal']) {
    assert.equal(isBlockedHostname(host), true, host);
  }
  for (const host of ['example.com', '93.184.215.14', '8.8.8.8', '[2606:4700::1111]', 'local.example.com']) {
    assert.equal(isBlockedHostname(host), false, host);
  }
  assert.equal(isPrivateAddress('172.32.0.1'), false);
  assert.equal(isPrivateAddress('::ffff:8.8.8.8'), false);
});
