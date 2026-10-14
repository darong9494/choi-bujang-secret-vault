import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createResponder, getActiveDenials } from '../xdr/exfiltration/respond.mjs';
import { checkAccess } from '../xdr/exfiltration/check-access.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide as decideZtna } from '../src/decider.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json', import.meta.url), 'utf8'));
const { normal, suspicious } = fixtureRequests();
const requestAlert = { data: { url: '/api/notes/demo' } };
const now = Date.parse(fixture.alerts[0].timestamp) + 1000;
const binding = { agentName: fixture.alerts[0].agent.name, deviceId: normal.deviceId,
  classId: normal.classId, projectId: normal.projectId };
const fresh = event => ({ ...event, timestamp: new Date(now - 1000).toISOString() });

async function setup(t) {
  const directory = await mkdtemp(join(tmpdir(), 'exfiltration-respond-'));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  });
  const options = { rulesPath: join(directory, 'rules.json'), logPath: join(directory, 'alerts.log'), clock: () => now };
  return { options, respond: createResponder(options) };
}

test('ambiguous events only alert and normal events never create denial rules', async t => {
  const { options, respond } = await setup(t);
  await writeFile(options.logPath, '{"moduleKey":"privilege"}\n');
  for (const event of fixture.alerts.slice(10)) {
    const out = await respond(fresh(event), { binding });
    assert.equal(out.installed, 0);
    assert.equal(out.ruleId, null);
    const access = await checkAccess(normal, requestAlert, { binding, destination: event.data.dstip,
      events: [fresh(event)], now, rulesPath: options.rulesPath });
    assert.equal(access.proceed, true, event.id);
    assert.equal(access.destinationDenial, null);
  }
  await assert.rejects(readFile(options.rulesPath), { code: 'ENOENT' });
  const rows = (await readFile(options.logPath, 'utf8')).trimEnd().split('\n').map(JSON.parse);
  assert.equal(rows.length, 11);
  assert.equal(rows[0].moduleKey, 'privilege');
  assert.ok(rows.slice(1).every(row => row.action === 'alert' && row.moduleKey === 'exfiltration'));
});

test('clear events persist only exact destinations and verified device scope; replay preserves expiry', async t => {
  const { options, respond } = await setup(t);
  await Promise.all(fixture.alerts.slice(0, 10).map(event => respond(fresh(event), { binding })));
  const before = await readFile(options.rulesPath, 'utf8');
  const state = JSON.parse(before);
  assert.equal(state.rules.length, new Set(fixture.alerts.slice(0, 10).map(event => event.data.dstip)).size);
  assert.deepEqual(state.rules.flatMap(rule => rule.evidenceAlertIds).sort(), fixture.alerts.slice(0, 10).map(event => event.id));
  for (const rule of state.rules) {
    assert.equal(rule.action, 'deny');
    assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), 600000);
    assert.deepEqual(Object.keys(rule).sort(), ['action', 'createdAt', 'evidenceAlertIds', 'expiresAt', 'id', 'scopeHash']);
  }
  for (const event of fixture.alerts.slice(0, 10)) {
    const context = { destination: event.data.dstip, now, events: [], rulesPath: options.rulesPath };
    const access = await checkAccess(normal, requestAlert, context);
    assert.equal(access.proceed, false, event.id);
    assert.ok(access.destinationDenial.evidenceAlertIds.includes(event.id));
    assert.deepEqual(access.ztna, await decideZtna(normal));
    for (const changes of [{ destination: '203.0.113.200' }, { now: now + 600000 }]) {
      assert.equal((await checkAccess(normal, requestAlert, { ...context, ...changes })).proceed, true);
    }
    for (const changes of [{ deviceId: 'f'.repeat(16) }, { projectId: 'other-project' }, { classId: 'other-class' }]) {
      assert.equal((await checkAccess({ ...normal, ...changes }, requestAlert, context)).proceed, true);
    }
    await respond(fresh(event), { binding });
  }
  assert.equal(await readFile(options.rulesPath, 'utf8'), before);
  const log = await readFile(options.logPath, 'utf8');
  assert.equal(log.trimEnd().split('\n').length, 20);
  assert.doesNotMatch(log + before, /srcuser|srcip|dstip|user01|203\.0\.113\.50/u);
  assert.equal((await checkAccess(suspicious, requestAlert, { now, rulesPath: options.rulesPath })).proceed, false);
  assert.equal((await checkAccess({ ...normal, deviceRegistered: false }, requestAlert, {})).proceed, false);
});

test('no rules from unsafe or missing IDs, unverified binding, invalid time or forged decisions', async t => {
  const { options, respond } = await setup(t);
  const event = fresh(fixture.alerts[0]);
  for (const [alert, context] of [
    [event, {}],
    [event, { binding: { ...binding, agentName: 'other-pc' } }],
    [event, { binding: { ...binding, deviceId: 'invalid' } }],
    [{ ...event, id: 'Bearer synthetic-test' }, { binding }],
    [{ ...event, timestamp: null }, { binding }],
    [{ ...event, timestamp: new Date(now + 1).toISOString() }, { binding }],
    [{ ...event, timestamp: new Date(now - 600000).toISOString() }, { binding }],
    [{ ...fresh(fixture.alerts[20]), action: 'block', confidence: 1 }, { binding }],
    [{ ...event, data: { ...event.data, dstip: '203.0.113.50.evil' } }, { binding }],
  ]) assert.equal((await respond(alert, context)).installed, 0);
  assert.equal((await getActiveDenials(normal, { ...options, destination: event.data.dstip })).length, 0);
  assert.ok(!(await readFile(options.logPath, 'utf8')).includes('synthetic-test'));
});

test('invalid storage fails without overwrite and TTL is bounded', async t => {
  const { options, respond } = await setup(t);
  await writeFile(options.rulesPath, 'invalid state');
  await assert.rejects(respond(fresh(fixture.alerts[0]), { binding }), /exfiltration_rules_invalid/u);
  assert.equal(await readFile(options.rulesPath, 'utf8'), 'invalid state');
  assert.throws(() => createResponder({ ttlMs: 0 }), /invalid_rule_ttl/u);
  assert.throws(() => createResponder({ ttlMs: 3600001 }), /invalid_rule_ttl/u);
});
