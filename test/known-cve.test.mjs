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
  assert.equal(decide(null).action, 'alert');
  assert.equal(decide({ data: { useragent: {} } }).action, 'alert');
  assert.equal(decide({ data: { url: 'x'.repeat(16385) } }).action, 'alert');
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
