import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/privilege/decide.mjs';
import { assessEvents } from '../xdr/privilege/assess-events.mjs';
import { checkAccess } from '../xdr/privilege/check-access.mjs';
import { decide as decideZtna } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json', import.meta.url), 'utf8'));
const patterns = JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json', import.meta.url), 'utf8')).patterns;
const initialTime = Date.parse(fixture.alerts[0].timestamp);
const agentName = fixture.alerts[0].agent.name;
const account = fixture.alerts[0].data.srcuser;
const { normal, suspicious } = fixtureRequests();
const requestAlert = { data: { url: '/api/notes/demo' } };
const binding = { agentName, sourceAccount: account, subjectId: normal.subjectId,
  classId: normal.classId, projectId: normal.projectId };

test('standalone privilege decisions distinguish 9 clear, 8 ambiguous and 9 normal events', async t => {
  const source = await readFile(new URL('../xdr/privilege/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\bimport\b|\brequire\s*\(|\bfetch\s*\(|\bprocess\b/u);
  assert.deepEqual(JSON.parse(source.slice(source.indexOf('['), source.indexOf('.map(pattern'))), patterns);
  t.mock.method(globalThis, 'fetch', () => { throw new Error('Offline test'); });
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  assert.deepEqual(Object.keys(isolated), ['decide']);
  for (const [index, event] of fixture.alerts.entries()) {
    const result = isolated.decide(event);
    assert.deepEqual(Object.keys(result).sort(), ['action', 'confidence', 'reason']);
    assert.equal(result.action, index < 9 ? 'block' : index < 17 ? 'alert' : 'record', event.id);
    assert.ok(Number.isFinite(result.confidence) && result.confidence >= 0 && result.confidence <= 1);
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
    assert.doesNotMatch(result.reason, /[\r\n]/u);
    assert.ok(!result.reason.includes(event.data.srcuser));
    if (result.action !== 'record') assert.ok(patterns.some(pattern => pattern.name === result.reason));
    assert.equal(decide({ ...event, id: 'changed', rule: { ...event.rule, level: 99 },
      data: { ...event.data, srcuser: 'another-account', srcip: '192.0.2.99' } }).action, result.action);
  }
});

test('single failures, cancellations, non-admin groups and missing account information never block', () => {
  for (const event of [null, {}, { data: { srcuser: {} } },
    { ...fixture.alerts[0], data: { ...fixture.alerts[0].data, srcuser: undefined } },
    { ...fixture.alerts[0], data: { ...fixture.alerts[0].data, group: 'project-week3' } },
    ...fixture.alerts.slice(9, 17)]) assert.notEqual(decide(event).action, 'block');
  assert.equal(decide(fixture.alerts[20]).action, 'record');
});

test('baseline accounts are optional evidence; missing lists are never invented', () => {
  const context = { agentName, account, now: initialTime + 1000 };
  const unknown = assessEvents([fixture.alerts[0]], context);
  assert.equal(unknown.baselineStatus, 'unavailable');
  assert.equal(unknown.findings[0].baselineRole, 'unknown');
  const known = assessEvents([fixture.alerts[0]], { ...context, knownAdminAccounts: [account.toUpperCase()] });
  assert.equal(known.findings[0].baselineRole, 'known_admin');
  assert.equal(known.findings[0].action, 'block'); // Baseline never overrides explicit abuse evidence.
  assert.equal(assessEvents([fixture.alerts[0]], { ...context, knownAdminAccounts: ['admin01'] })
    .findings[0].baselineRole, 'not_listed');
});

test('group addition and command use correlate only for the same account, PC and correct order', () => {
  const addition = { id: 'group-01', timestamp: new Date(initialTime).toISOString(), agent: { name: agentName },
    data: { srcuser: account, group: 'administrators' }, rule: { description: '계정이 관리자 그룹에 추가됐습니다.' } };
  const execution = { id: 'command-01', timestamp: new Date(initialTime + 60000).toISOString(), agent: { name: agentName },
    data: { srcuser: account }, rule: { description: '평소 주소에서 관리자 명령이 실행됐습니다.' } };
  assert.equal(decide(addition).action, 'alert');
  assert.equal(decide(execution).action, 'alert');
  const context = { agentName, account, now: initialTime + 400000 };
  assert.deepEqual(assessEvents([addition, execution], context).evidenceAlertIds, ['command-01', 'group-01']);
  for (const changed of [
    { ...execution, data: { srcuser: 'another-account' } },
    { ...execution, agent: { name: 'another-pc' } },
    { ...execution, timestamp: new Date(initialTime - 1000).toISOString() },
    { ...execution, timestamp: new Date(initialTime + 301000).toISOString() },
    { ...execution, rule: { description: '관리자 명령 실행이 실패했습니다.' } },
  ]) assert.deepEqual(assessEvents([addition, changed], context).evidenceAlertIds, []);
});

test('session restriction targets the verified account, expires, and keeps earlier defenses', async () => {
  const context = { binding, events: [fixture.alerts[0]], now: initialTime + 1000 };
  const result = await checkAccess(normal, requestAlert, context);
  assert.equal(result.proceed, false);
  assert.equal(result.revocation.action, 'revoke_sessions');
  assert.equal(result.revocation.subjectId, normal.subjectId);
  assert.deepEqual(result.revocation.evidenceAlertIds, ['pv-01']);
  assert.deepEqual(result.ztna, await decideZtna(normal));
  assert.equal((await checkAccess({ ...normal, subjectId: 'another-subject' }, requestAlert, context)).proceed, true);
  assert.equal((await checkAccess(normal, requestAlert, { ...context, binding: undefined })).revocation, null);
  assert.equal((await checkAccess(normal, requestAlert, { ...context, now: initialTime + 600000 })).proceed, true);
  for (const event of fixture.alerts.slice(9)) {
    const response = await checkAccess(normal, requestAlert, { binding: { ...binding, sourceAccount: event.data.srcuser },
      events: [event], now: Date.parse(event.timestamp) + 1000 });
    assert.equal(response.proceed, true, event.id);
    assert.equal(response.revocation, null);
  }
  for (const request of [suspicious, { ...normal, deviceRegistered: false }]) {
    assert.equal((await checkAccess(request, requestAlert, {})).proceed, false);
  }
  const persistence = JSON.parse(await readFile(new URL('../xdr/fixtures/persistence.json', import.meta.url), 'utf8'));
  assert.equal((await checkAccess(normal, requestAlert, { persistence: {
    binding: { agentName, deviceId: normal.deviceId, classId: normal.classId, projectId: normal.projectId },
    events: [persistence.alerts[0]], now: Date.parse(persistence.alerts[0].timestamp) + 1000,
  } })).proceed, false);
  const cve = JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));
  assert.equal((await checkAccess(normal, cve.alerts[0], {})).proceed, false);
});
