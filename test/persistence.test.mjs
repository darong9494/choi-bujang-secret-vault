import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/persistence/decide.mjs';
import { assessEvents } from '../xdr/persistence/assess-events.mjs';
import { checkAccess } from '../xdr/persistence/check-access.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide as decideZtna } from '../src/decider.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/persistence.json', import.meta.url), 'utf8'));
const patterns = JSON.parse(await readFile(new URL('../xdr/persistence/patterns.json', import.meta.url), 'utf8')).patterns;
const agentName = fixture.alerts[0].agent.name;
const eventTime = Date.parse(fixture.alerts[0].timestamp);
const requestAlert = { data: { url: '/api/notes/demo' } };
const { normal, suspicious } = fixtureRequests();
const binding = { agentName, deviceId: normal.deviceId, classId: normal.classId, projectId: normal.projectId };

test('fixture classification is independent of IDs, severity and account; pure module works alone', async t => {
  t.mock.method(globalThis, 'fetch', () => { throw new Error('Offline test'); });
  const source = await readFile(new URL('../xdr/persistence/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\bimport\b|\brequire\s*\(|\bfetch\s*\(|\bprocess\b/u);
  assert.deepEqual(JSON.parse(source.slice(source.indexOf('['), source.indexOf('.map(pattern'))), patterns);
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  assert.deepEqual(Object.keys(isolated), ['decide']);
  for (const [index, event] of fixture.alerts.entries()) {
    const result = isolated.decide(event);
    assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason']);
    assert.equal(result.action, index < 8 ? 'block' : index < 16 ? 'alert' : 'record', event.id);
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(Number.isFinite(result.confidence) && result.confidence >= 0 && result.confidence <= 1);
    assert.ok(!result.reason.includes(event.data.srcuser));
    assert.doesNotMatch(result.reason, /[\r\n]/u);
    assert.equal(decide({ ...event, id: 'different', rule: { ...event.rule, level: 99 },
      data: { ...event.data, srcuser: 'other-account', srcip: '192.0.2.99' } }).action, result.action);
  }
});

test('an unsigned or temporary file alone and unknown signatures cannot trigger a block', () => {
  for (const event of [null, {}, { data: { path: {} } },
    { rule: { description: '서명이 없습니다.' }, data: fixture.alerts[0].data },
    { rule: { description: '새 서비스가 등록됐습니다. 서명은 확인되지 않았습니다.' }, data: fixture.alerts[0].data },
    { rule: { description: '임시 폴더에 실행 파일이 하나 생겼습니다. 서비스 등록은 없습니다.' }, data: fixture.alerts[0].data }]) {
    assert.notEqual(decide(event).action, 'block');
  }
});

test('unavailable baseline remains unknown; only an actual provided list proves a difference', () => {
  const event = { id: 'fim-01', timestamp: new Date(eventTime).toISOString(), agent: { name: agentName },
    rule: { description: '파일이 생성됐습니다.' }, data: { path: fixture.alerts[0].data.path } };
  const context = { agentName, now: eventTime + 1000 };
  const unknown = assessEvents([event], context);
  assert.equal(unknown.baselineStatus, 'unavailable');
  assert.equal(unknown.findings[0].baselineStatus, 'unknown');
  const unlisted = assessEvents([event], { ...context, baselinePaths: ['C:\\lab\\approved.exe'] });
  assert.equal(unlisted.findings[0].baselineStatus, 'unlisted');
  assert.equal(unlisted.findings[0].action, 'alert');
  assert.deepEqual(unlisted.evidenceAlertIds, []);
  const listed = assessEvents([event], { ...context, baselinePaths: [event.data.path.toUpperCase()] });
  assert.equal(listed.findings[0].baselineStatus, 'listed');
  assert.equal(listed.findings[0].action, 'record');
  const attack = assessEvents([fixture.alerts[0]], { ...context, baselinePaths: [event.data.path] });
  assert.equal(attack.findings[0].action, 'block');
});

test('FIM and registration correlate only for the same PC, file and short window', () => {
  const file = { id: 'fim-01', timestamp: new Date(eventTime).toISOString(), agent: { name: agentName },
    rule: { description: '파일 무결성 변경: 서명이 없습니다.' }, data: { path: fixture.alerts[0].data.path } };
  const registration = { ...file, id: 'service-01', timestamp: new Date(eventTime + 60000).toISOString(),
    rule: { description: '새 서비스가 등록됐습니다.' } };
  assert.notEqual(decide(file).action, 'block');
  assert.notEqual(decide(registration).action, 'block');
  const context = { agentName, now: eventTime + 400000 };
  assert.deepEqual(assessEvents([file, registration], context).evidenceAlertIds, ['fim-01', 'service-01']);
  for (const changed of [
    { ...registration, agent: { name: 'another-pc' } },
    { ...registration, data: { path: 'C:\\Temp\\other.exe' } },
    { ...registration, timestamp: new Date(eventTime + 301000).toISOString() },
  ]) assert.deepEqual(assessEvents([file, changed], context).evidenceAlertIds, []);
});

test('quarantine affects only the verified device, expires, and preserves existing checks', async () => {
  const context = { binding, events: [fixture.alerts[0]], now: eventTime + 1000 };
  const quarantined = await checkAccess(normal, requestAlert, context);
  assert.equal(quarantined.proceed, false);
  assert.equal(quarantined.quarantine.deviceId, normal.deviceId);
  assert.deepEqual(quarantined.quarantine.evidenceAlertIds, ['ps-01']);
  assert.deepEqual(quarantined.ztna, await decideZtna(normal));
  assert.equal((await checkAccess(normal, requestAlert, { ...context,
    binding: { ...binding, deviceId: 'f'.repeat(16) } })).proceed, true);
  assert.equal((await checkAccess(normal, requestAlert, { ...context, binding: undefined })).quarantine, null);
  assert.equal((await checkAccess(normal, requestAlert, { ...context, now: eventTime + 600000 })).proceed, true);
  assert.equal((await checkAccess(normal, requestAlert, { ...context, now: eventTime - 1 })).proceed, true);
  for (const event of fixture.alerts.slice(8)) {
    const result = await checkAccess(normal, requestAlert,
      { binding, events: [event], now: Date.parse(event.timestamp) + 1000 });
    assert.equal(result.proceed, true, event.id);
    assert.equal(result.quarantine, null);
  }
  for (const request of [suspicious, { ...normal, deviceRegistered: false }]) {
    assert.equal((await checkAccess(request, requestAlert, {})).proceed, false);
  }
  const cve = JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));
  assert.equal((await checkAccess(normal, cve.alerts[0], {})).proceed, false);
});
