import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/known-cve/decide.mjs';
import { checkAccess } from '../xdr/known-cve/check-access.mjs';
import { decide as decideZtna, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));
const documented = JSON.parse(await readFile(new URL('../xdr/known-cve/patterns.json', import.meta.url), 'utf8'));

test('24 source events separate into clear blocks, ambiguous alerts and ordinary records', () => {
  for (const [index, alert] of fixture.alerts.entries()) {
    const result = decide(alert);
    assert.equal(result.action, index < 8 ? 'block' : index < 16 ? 'alert' : 'record', alert.id);
    assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason']);
    assert.ok(Number.isFinite(result.confidence) && result.confidence >= 0 && result.confidence <= 1);
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
    assert.doesNotMatch(result.reason, /[\r\n]/u);
    assert.ok(!result.reason.includes(alert.data.srcip));
    if (result.action !== 'record') assert.ok(documented.patterns.some(pattern => pattern.name === result.reason));
  }
});

test('only actual request shape can block; IDs, source, labels, level and count cannot', () => {
  for (const alert of fixture.alerts) {
    assert.equal(decide({ ...alert, id: 'changed', agent: null,
      data: { ...alert.data, srcip: '192.0.2.1', srcuser: 'user01', count: '9999' },
      rule: { ...alert.rule, level: 99 } }).action, decide(alert).action);
  }
  const maliciousRequest = { data: fixture.alerts[0].data,
    rule: { level: 0, description: '일반 요청' } };
  assert.equal(decide(maliciousRequest).action, 'block');
  const descriptionOnly = { data: { url: '/health' }, rule: fixture.alerts[0].rule };
  assert.equal(decide(descriptionOnly).action, 'alert');
  assert.equal(decide({ data: { url: '/health' }, rule: { level: 99, mitre: ['T1190'] } }).action, 'record');
});

test('missing or malformed optional fields do not throw or create a block', () => {
  for (const alert of [null, undefined, {}, [], 'text', { data: null },
    { data: { useragent: {}, url: 123 }, rule: { description: {} } }]) {
    assert.deepEqual(decide(alert), { action: 'record', confidence: 0, reason: '일치하는 알려진 악용 패턴 없음' });
  }
});

test('standalone module has the documented constants and works without file or network dependencies', async t => {
  const source = await readFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\bimport\b|\brequire\s*\(|\bfetch\s*\(|\bprocess\b/u);
  assert.deepEqual(JSON.parse(source.slice(source.indexOf('['), source.indexOf('.map(pattern'))), documented.patterns);
  assert.ok(documented.patterns.every(pattern => ['name', 'condition', 'evidence']
    .every(key => typeof pattern[key] === 'string' && pattern[key].trim() && !/[\r\n]/u.test(pattern[key]))));
  t.mock.method(globalThis, 'fetch', () => { throw new Error('Network unavailable'); });
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  assert.deepEqual(Object.keys(isolated), ['decide']);
  for (const alert of fixture.alerts) assert.deepEqual(isolated.decide(alert), decide(alert));
});

test('ZTNA composition preserves all existing decisions and alerts never deny an otherwise allowed request', async () => {
  const { normal, suspicious } = fixtureRequests();
  for (const request of [normal, suspicious, { ...normal, deviceRegistered: false }]) {
    const original = await decideZtna(request);
    for (const alert of fixture.alerts) {
      const output = await checkAccess(request, alert);
      assert.deepEqual(output.ztna, original);
      assert.ok(output.ztna.ruleIds.every(id => RULE_IDS.includes(id)));
      assert.equal(output.proceed, original.decision === 'allow' && output.inspection.action !== 'block');
      assert.equal(output.notify, output.inspection.action !== 'record');
    }
  }
});
