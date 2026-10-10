import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyXfo, evaluateFraming, parseCsp, parseXfo, sourceListMatches } from './policy.ts';

const R = 'https://www.target.com/page';

const allowed = (headers: { xfo?: string; csp?: string }, embedder?: string, resource = R) =>
  evaluateFraming({ xFrameOptions: headers.xfo ?? null, csp: headers.csp ?? null, resourceUrl: resource, embedderOrigin: embedder }).allowed;

test('no headers → any site can embed', () => {
  const r = evaluateFraming({ xFrameOptions: null, csp: null, resourceUrl: R });
  assert.equal(r.allowed, true);
  assert.equal(r.decidedBy, 'none');
  assert.deepEqual(r.audience, { kind: 'anyone' });
});

test('X-Frame-Options values', () => {
  assert.equal(allowed({ xfo: 'DENY' }), false);
  assert.equal(allowed({ xfo: 'deny' }, 'https://www.target.com'), false);
  assert.equal(allowed({ xfo: 'SAMEORIGIN' }), false);
  assert.equal(allowed({ xfo: 'SAMEORIGIN' }, 'https://www.target.com'), true);
  assert.equal(allowed({ xfo: 'sameorigin' }, 'https://target.com'), false, 'different host is a different origin');
  // ALLOW-FROM is not supported by current browsers, so it does not block.
  assert.equal(allowed({ xfo: 'ALLOW-FROM https://partner.com' }), true);
  assert.equal(allowed({ xfo: 'ALLOWALL' }), true);
  assert.equal(allowed({ xfo: 'garbage' }), true);
});

test('X-Frame-Options with several values follows the HTML Standard', () => {
  assert.equal(classifyXfo(parseXfo('DENY, DENY')), 'deny', 'duplicates collapse');
  assert.equal(classifyXfo(parseXfo('SAMEORIGIN, DENY')), 'conflict');
  assert.equal(allowed({ xfo: 'SAMEORIGIN, DENY' }, 'https://www.target.com'), false, 'conflicts block');
  assert.equal(classifyXfo(parseXfo('foo, bar')), 'unrecognised');
  assert.equal(allowed({ xfo: 'foo, bar' }), true);
});

test("frame-ancestors 'none' and empty lists block everyone", () => {
  assert.equal(allowed({ csp: "frame-ancestors 'none'" }), false);
  assert.equal(allowed({ csp: "frame-ancestors 'none'" }, 'https://www.target.com'), false);
  assert.equal(allowed({ csp: 'frame-ancestors' }), false);
  assert.deepEqual(evaluateFraming({ xFrameOptions: null, csp: "frame-ancestors 'none'", resourceUrl: R }).audience, { kind: 'nobody' });
});

test("frame-ancestors 'self'", () => {
  assert.equal(allowed({ csp: "frame-ancestors 'self'" }), false);
  assert.equal(allowed({ csp: "frame-ancestors 'self'" }, 'https://www.target.com'), true);
  assert.equal(allowed({ csp: "frame-ancestors 'SELF'" }, 'https://www.target.com'), true, 'keywords are case-insensitive');
  // An http page's 'self' also covers the https version of the same host.
  assert.equal(allowed({ csp: "frame-ancestors 'self'" }, 'https://www.target.com', 'http://www.target.com/'), true);
  assert.equal(allowed({ csp: "frame-ancestors 'self'" }, 'http://www.target.com', 'https://www.target.com/'), false);
});

test('frame-ancestors host sources', () => {
  const csp = 'frame-ancestors https://partner.com *.friends.org';
  assert.equal(allowed({ csp }), false);
  assert.equal(allowed({ csp }, 'https://partner.com'), true);
  assert.equal(allowed({ csp }, 'http://partner.com'), false, 'explicit https: scheme');
  assert.equal(allowed({ csp }, 'https://a.friends.org'), true);
  assert.equal(allowed({ csp }, 'https://a.b.friends.org'), true);
  assert.equal(allowed({ csp }, 'https://friends.org'), false, '*.x does not match x itself');
  assert.equal(allowed({ csp }, 'https://partner.com:8443'), false, 'non-default port');
  assert.equal(allowed({ csp: 'frame-ancestors partner.com:*' }, 'https://partner.com:8443'), true);
  assert.equal(allowed({ csp: 'frame-ancestors PARTNER.com' }, 'https://partner.com'), true);
  // No scheme: takes the protected resource's scheme; http resources also accept https ancestors.
  assert.equal(allowed({ csp: 'frame-ancestors partner.com' }, 'http://partner.com'), false);
  assert.equal(allowed({ csp: 'frame-ancestors partner.com' }, 'https://partner.com', 'http://www.target.com/'), true);
  assert.equal(allowed({ csp: 'frame-ancestors http://partner.com' }, 'https://partner.com'), true, 'http: upgrades to https:');
});

test('frame-ancestors wildcards and scheme sources', () => {
  assert.equal(allowed({ csp: 'frame-ancestors *' }), true);
  assert.equal(allowed({ csp: 'frame-ancestors https:' }), true);
  assert.equal(allowed({ csp: 'frame-ancestors https:' }, 'http://site.com'), false);
  assert.equal(allowed({ csp: 'frame-ancestors http:' }, 'https://site.com'), true);
  assert.equal(allowed({ csp: 'frame-ancestors https://*' }), true);
  assert.deepEqual(evaluateFraming({ xFrameOptions: null, csp: 'frame-ancestors *', resourceUrl: R }).audience, { kind: 'anyone' });
});

test("'none' mixed with other sources is ignored", () => {
  assert.equal(allowed({ csp: "frame-ancestors 'none' https://partner.com" }, 'https://partner.com'), true);
});

test('frame-ancestors overrides X-Frame-Options', () => {
  const r = evaluateFraming({ xFrameOptions: 'DENY', csp: 'frame-ancestors *', resourceUrl: R });
  assert.equal(r.allowed, true);
  assert.equal(r.decidedBy, 'csp');
  assert.equal(r.xfo.ignored, true);
  assert.equal(allowed({ xfo: 'SAMEORIGIN', csp: 'frame-ancestors https://partner.com' }, 'https://partner.com'), true);
  // …but a CSP without frame-ancestors leaves X-Frame-Options in charge.
  assert.equal(allowed({ xfo: 'DENY', csp: "default-src 'self'" }), false);
});

test('report-only policies never block', () => {
  const r = evaluateFraming({ xFrameOptions: null, csp: null, cspReportOnly: "frame-ancestors 'none'", resourceUrl: R });
  assert.equal(r.allowed, true);
  assert.equal(r.csp.reportOnly.length, 1);
  assert.equal(r.csp.reportOnly[0]!.allows, false);
});

test('several policies must all allow', () => {
  const csp = "frame-ancestors *, frame-ancestors 'self'";
  assert.equal(parseCsp(csp).length, 2);
  assert.equal(allowed({ csp }), false);
  assert.equal(allowed({ csp }, 'https://www.target.com'), true);
});

test('CSP parsing: duplicates and odd whitespace', () => {
  const [policy] = parseCsp("default-src 'self' ;  FRAME-ANCESTORS\t'self'   https://a.com ; frame-ancestors *");
  assert.deepEqual(policy!.directives['frame-ancestors'], ["'self'", 'https://a.com']);
  assert.equal(allowed({ csp: "script-src 'self'; frame-ancestors 'self'; frame-ancestors *" }), false, 'first directive wins');
});

test('real-world headers', () => {
  // google.com
  assert.equal(allowed({ xfo: 'SAMEORIGIN' }), false);
  // facebook.com (shape of their header)
  assert.equal(allowed({ xfo: 'DENY', csp: "default-src data: blob: 'self' https://*.fbsbx.com; frame-ancestors https://www.facebook.com" }), false);
  // github.com
  assert.equal(allowed({ xfo: 'deny', csp: "default-src 'none'; frame-ancestors 'none'" }), false);
  // youtube embeds
  assert.equal(allowed({ csp: "require-trusted-types-for 'script'" }), true);
});

test('audience for listed and self+listed sources', () => {
  const listed = evaluateFraming({ xFrameOptions: null, csp: 'frame-ancestors https://partner.com', resourceUrl: R }).audience;
  assert.deepEqual(listed, { kind: 'listed', sources: ['https://partner.com'] });
  const self = evaluateFraming({ xFrameOptions: null, csp: "frame-ancestors 'self'", resourceUrl: R }).audience;
  assert.deepEqual(self, { kind: 'same-origin', origin: 'https://www.target.com' });
  const both = evaluateFraming({ xFrameOptions: null, csp: "frame-ancestors 'self' partner.com", resourceUrl: R }).audience;
  assert.deepEqual(both, { kind: 'listed', sources: ["'self'", 'partner.com'] });
});

test('sourceListMatches edge cases', () => {
  assert.equal(sourceListMatches(["'unsafe-inline'"], 'https://a.com', R), false);
  assert.equal(sourceListMatches(['https://a.com/'], 'https://a.com', R), true, 'root path matches an origin');
  assert.equal(sourceListMatches(['https://a.com/app'], 'https://a.com', R), false, 'longer paths never match an origin');
});
