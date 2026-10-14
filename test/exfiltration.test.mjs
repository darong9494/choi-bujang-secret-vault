import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { checkAccess } from '../xdr/exfiltration/check-access.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide as decideZtna } from '../src/decider.mjs';

const fixtureUrl = new URL('../xdr/fixtures/exfiltration.json', import.meta.url);
const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
const { normal, suspicious } = fixtureRequests();
const requestAlert = { data: { url: '/api/notes/demo' } };
const event = fixture.alerts[0];
const now = Date.parse(event.timestamp) + 1000;
const binding = { agentName: event.agent.name, deviceId: normal.deviceId,
  classId: normal.classId, projectId: normal.projectId };

test('offline decisions separate 10 clear, 10 ambiguous and 10 normal events without ID shortcuts', async t => {
  const source = await readFile(new URL('../xdr/exfiltration/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\bimport\b|\brequire\s*\(|\bfetch\s*\(|\bprocess\b/u);
  const patterns = JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json', import.meta.url), 'utf8')).patterns;
  assert.deepEqual(JSON.parse(source.slice(source.indexOf('['), source.indexOf('.map(pattern'))), patterns);
  t.mock.method(globalThis, 'fetch', () => { throw new Error('offline'); });
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  assert.deepEqual(Object.keys(isolated), ['decide']);
  for (const [i, alert] of fixture.alerts.entries()) {
    const result = isolated.decide(alert);
    assert.equal(result.action, i < 10 ? 'block' : i < 20 ? 'alert' : 'record', alert.id);
    assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason']);
    assert.ok(Number.isFinite(result.confidence) && result.confidence >= 0 && result.confidence <= 1);
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
    assert.doesNotMatch(result.reason, /[\r\n]/u);
    const altered = { ...alert, id: 'changed', rule: { ...alert.rule, level: 99, mitre: [] },
      data: { ...alert.data, srcuser: 'another-account', srcip: '192.0.2.99',
        ...(alert.data.dstip ? { dstip: '203.0.113.99' } : {}) } };
    assert.equal(isolated.decide(altered).action, result.action);
  }
});

test('missing, negative, infinite or invalid volume/destination and failures never authorize a block', () => {
  for (const bytes of [undefined, null, -1, Infinity, NaN, {}, 'invalid', '', '9007199254740992']) {
    assert.notEqual(decide({ ...event, data: { ...event.data, bytes } }).action, 'block');
  }
  for (const dstip of [undefined, 'Bearer synthetic-test', '999.0.0.1', '203.0.113.50.evil']) {
    assert.notEqual(decide({ ...event, data: { ...event.data, dstip } }).action, 'block');
  }
  for (const text of ['처음 보는 목적지로 큰 전송이 실패했습니다.', '처음 보는 목적지로 전송하지 않았습니다.']) {
    assert.notEqual(decide({ ...event, rule: { description: text } }).action, 'block');
  }
  assert.equal(decide(null).action, 'record');
});

test('destination gate is exact, scoped, expires and never replaces earlier ZTNA decisions', async () => {
  const context = { binding, destination: event.data.dstip, events: [event], now };
  const blocked = await checkAccess(normal, requestAlert, context);
  assert.equal(blocked.proceed, false);
  assert.deepEqual(blocked.destinationDenial.evidenceAlertIds, [event.id]);
  assert.deepEqual(blocked.ztna, await decideZtna(normal));
  assert.equal(blocked.exfiltration.baselineStatus, 'unavailable');
  for (const changes of [{ destination: '203.0.113.99' }, { binding: undefined },
    { binding: { ...binding, agentName: 'other-pc' } }, { now: Date.parse(event.timestamp) + 600000 },
    { now: Date.parse(event.timestamp) - 1 }, { events: [{ ...event, id: 'unsafe id' }] }]) {
    assert.equal((await checkAccess(normal, requestAlert, { ...context, ...changes })).proceed, true);
  }
  assert.equal((await checkAccess({ ...normal, projectId: 'other-project' }, requestAlert, context)).proceed, true);
  assert.equal((await checkAccess(suspicious, requestAlert, {})).proceed, false);
  assert.equal((await checkAccess({ ...normal, deviceRegistered: false }, requestAlert, {})).proceed, false);
  for (const alert of fixture.alerts.slice(10)) {
    const result = await checkAccess(normal, requestAlert, { ...context, events: [alert],
      destination: alert.data.dstip, now: Date.parse(alert.timestamp) + 1000 });
    assert.equal(result.proceed, true, alert.id);
    assert.equal(result.destinationDenial, null);
  }
});

test('verified baseline anomalies notify without inventing a baseline or denying normal transfers', async () => {
  const alert = fixture.alerts[20];
  const context = { binding, destination: alert.data.dstip, events: [alert], now: Date.parse(alert.timestamp) + 1000 };
  const unknown = await checkAccess(normal, requestAlert, context);
  assert.equal(unknown.exfiltration.findings[0].volumeStatus, 'unknown');
  const result = await checkAccess(normal, requestAlert, { ...context,
    baseline: { destinations: [], maxBytes: 100 } });
  assert.equal(result.exfiltration.findings[0].action, 'alert');
  assert.equal(result.notify, true);
  assert.equal(result.proceed, true);
  assert.equal(result.destinationDenial, null);
});
