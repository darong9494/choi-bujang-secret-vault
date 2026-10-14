import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createResponder, getActiveDenials } from '../xdr/persistence/respond.mjs';
import { checkAccess } from '../xdr/persistence/check-access.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide as decideZtna } from '../src/decider.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/persistence.json', import.meta.url), 'utf8'));
const initialTime = Date.parse(fixture.alerts[0].timestamp);
const { normal, suspicious } = fixtureRequests();
const binding = { agentName: fixture.alerts[0].agent.name, deviceId: normal.deviceId,
  classId: normal.classId, projectId: normal.projectId };
const requestAlert = { data: { url: '/api/notes/demo' } };
// Replay scenarios at a fixed test time without changing the source fixture.
const fresh = alert => ({ ...alert, timestamp: new Date(initialTime).toISOString() });

async function setup(t) {
  const directory = await mkdtemp(join(tmpdir(), 'persistence-respond-'));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  });
  const options = { rulesPath: join(directory, 'rules.json'), logPath: join(directory, 'alerts.log'),
    clock: () => initialTime + 1000, ttlMs: 600000 };
  return { options, respond: createResponder(options) };
}

test('ambiguous and normal events log only alerts, never deny an otherwise normal device', async t => {
  const { options, respond } = await setup(t);
  await writeFile(options.logPath, '{"moduleKey":"known-cve"}\n');
  for (const event of fixture.alerts.slice(8)) {
    const result = await respond(fresh(event), { binding });
    assert.equal(result.installed, 0);
    assert.equal(result.ruleId, null);
    const access = await checkAccess(normal, requestAlert,
      { binding, events: [fresh(event)], now: initialTime + 1000, rulesPath: options.rulesPath });
    assert.equal(access.proceed, true, event.id);
    assert.equal(access.quarantine, null);
  }
  await assert.rejects(readFile(options.rulesPath), { code: 'ENOENT' });
  const lines = (await readFile(options.logPath, 'utf8')).trimEnd().split('\n').map(JSON.parse);
  assert.equal(lines.length, 9);
  assert.equal(lines[0].moduleKey, 'known-cve');
  assert.ok(lines.slice(1).every(row => row.moduleKey === 'persistence' && row.action === 'alert'));
});

test('clear attacks install a scoped denial that applies to subsequent requests without replaying events', async t => {
  const { options, respond } = await setup(t);
  await Promise.all(fixture.alerts.slice(0, 8).map(event => respond(fresh(event), { binding })));
  const state = JSON.parse(await readFile(options.rulesPath, 'utf8'));
  assert.equal(state.rules.length, 1);
  const rule = state.rules[0];
  assert.equal(rule.action, 'deny');
  assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), 600000);
  assert.deepEqual([...rule.evidenceAlertIds].sort(), fixture.alerts.slice(0, 8).map(event => event.id));
  assert.deepEqual(Object.keys(rule).sort(), ['action', 'createdAt', 'evidenceAlertIds', 'expiresAt', 'id', 'scopeHash']);
  const context = { binding, events: [], now: initialTime + 1000, rulesPath: options.rulesPath };
  const access = await checkAccess(normal, requestAlert, context);
  assert.equal(access.proceed, false);
  assert.equal(access.persistenceDenyRules.length, 1);
  assert.equal(access.quarantine.deviceId, normal.deviceId);
  assert.deepEqual(access.ztna, await decideZtna(normal));
  const otherDevice = { ...normal, deviceId: normal.deviceId === 'f'.repeat(16) ? 'e'.repeat(16) : 'f'.repeat(16) };
  assert.equal((await checkAccess(otherDevice, requestAlert, { ...context, binding: undefined })).proceed, true);
  assert.equal((await checkAccess({ ...normal, projectId: 'other-project' }, requestAlert,
    { ...context, binding: undefined })).proceed, true);
  for (const event of fixture.alerts.slice(0, 8)) await respond(fresh(event), { binding });
  assert.deepEqual(JSON.parse(await readFile(options.rulesPath, 'utf8')), state);
  const log = await readFile(options.logPath, 'utf8');
  assert.equal(log.trimEnd().split('\n').length, 16);
  assert.doesNotMatch(log, /srcip|srcuser|203\.0\.113\.12|user01|helper\.exe/u);
});

test('expiry ends the denial and reads do not renew it or replace existing ZTNA decisions', async t => {
  const { options, respond } = await setup(t);
  await respond(fresh(fixture.alerts[0]), { binding });
  const before = await readFile(options.rulesPath, 'utf8');
  assert.equal((await getActiveDenials(normal, options)).length, 1);
  const context = { now: initialTime + 600000, rulesPath: options.rulesPath };
  assert.equal((await checkAccess(normal, requestAlert, context)).proceed, true);
  for (const request of [suspicious, { ...normal, deviceRegistered: false }]) {
    const output = await checkAccess(request, requestAlert, context);
    assert.equal(output.proceed, false);
    assert.deepEqual(output.ztna, await decideZtna(request));
  }
  assert.equal(await readFile(options.rulesPath, 'utf8'), before);
});

test('no rules from caller claims, unbound PCs, missing IDs, stale or future timestamps', async t => {
  const { options, respond } = await setup(t);
  assert.equal((await respond({ ...fresh(fixture.alerts[16]), action: 'block', confidence: 1 }, { binding })).installed, 0);
  for (const [event, context] of [
    [fresh(fixture.alerts[0]), {}],
    [fresh(fixture.alerts[0]), { binding: { ...binding, agentName: 'other-pc' } }],
    [{ ...fresh(fixture.alerts[0]), id: 'Bearer synthetic-test-secret' }, { binding }],
    [{ ...fresh(fixture.alerts[0]), timestamp: new Date(initialTime - 600000).toISOString() }, { binding }],
    [{ ...fresh(fixture.alerts[0]), timestamp: new Date(initialTime + 2000).toISOString() }, { binding }],
    [{ ...fresh(fixture.alerts[0]), timestamp: null }, { binding }],
  ]) assert.equal((await respond(event, context)).installed, 0);
  await assert.rejects(readFile(options.rulesPath), { code: 'ENOENT' });
  assert.ok(!(await readFile(options.logPath, 'utf8')).includes('synthetic-test-secret'));
});

test('invalid storage and invalid TTL are errors, not a successful installation', async t => {
  const { options, respond } = await setup(t);
  await writeFile(options.rulesPath, 'invalid state');
  await assert.rejects(respond(fresh(fixture.alerts[0]), { binding }), /persistence_rules_invalid/u);
  assert.equal(await readFile(options.rulesPath, 'utf8'), 'invalid state');
  assert.throws(() => createResponder({ ttlMs: 0 }), /invalid_rule_ttl/u);
  assert.throws(() => createResponder({ ttlMs: 3600001 }), /invalid_rule_ttl/u);
});
