import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/known-cve/decide.mjs';
import { checkAccess } from '../xdr/known-cve/check-access.mjs';
import { decide as baseDecide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { isDecision } from '../scripts/xdr-run.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));

test('existing clear, ambiguous, and ordinary fixtures have valid separate results', t => {
  t.mock.method(globalThis, 'fetch', () => { throw new Error('Network must not be used'); });
  const actions = fixture.alerts.map(alert => {
    const result = decide(alert);
    assert.ok(isDecision(result));
    assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason']);
    assert.ok(!result.reason.includes(alert.data.srcip));
    return result.action;
  });
  assert.deepEqual(actions.slice(0, 8), Array(8).fill('block'));
  assert.deepEqual(actions.slice(8, 16), Array(8).fill('alert'));
  assert.deepEqual(actions.slice(16), Array(8).fill('record'));
});

test('labels, severity and counts alone cannot cause a block', () => {
  const result = decide({ rule: { level: 99, description: 'CVE-2021-44228' },
    data: { url: '/health', count: '99999' } });
  assert.equal(result.action, 'alert');
  assert.equal(decide({ data: { url: '/health' } }).action, 'record');
  assert.equal(decide(null).action, 'record');
  assert.equal(decide({ data: { useragent: {} } }).action, 'record');
  assert.equal(decide({ data: { url: 'x'.repeat(16385) } }).action, 'record');
});

test('single-file offline module preserves documented patterns and score thresholds', async t => {
  const source = await readFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8');
  const documented = JSON.parse(await readFile(new URL('../xdr/known-cve/patterns.json', import.meta.url), 'utf8'));
  assert.doesNotMatch(source, /\bimport\b|\brequire\s*\(|\bfetch\s*\(/u);
  const embedded = JSON.parse(source.slice(source.indexOf('['), source.indexOf('.map(pattern')));
  assert.deepEqual(embedded, documented.patterns);
  t.mock.method(globalThis, 'fetch', () => { throw new Error('Offline module'); });
  // No filesystem base URL exists here, so a relative module dependency cannot resolve.
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  assert.deepEqual(Object.keys(isolated), ['decide']);
  for (const alert of [...fixture.alerts, null, {}, { data: { url: 123 } }]) {
    const out = isolated.decide(alert);
    assert.ok(isDecision(out));
    assert.equal(out.action, out.confidence >= 0.85 ? 'block' : out.confidence >= 0.5 ? 'alert' : 'record');
    assert.doesNotMatch(out.reason, /[\r\n]/u);
    if (out.confidence >= 0.5) assert.ok(documented.patterns.some(pattern => pattern.name === out.reason));
  }
});

test('inspection can restrict an allow but never bypass deny or step_up', async () => {
  const { normal, suspicious } = fixtureRequests();
  for (const request of [normal, { ...normal, deviceRegistered: false }, suspicious]) {
    for (const alert of [fixture.alerts[0], fixture.alerts[8], fixture.alerts[16]]) {
      const expected = await baseDecide(request);
      const output = await checkAccess(request, alert);
      assert.deepEqual(output.ztna, expected);
      assert.ok(output.ztna.ruleIds.every(id => RULE_IDS.includes(id)));
      assert.equal(output.proceed, expected.decision === 'allow' && output.inspection.action !== 'block');
    }
  }
});
