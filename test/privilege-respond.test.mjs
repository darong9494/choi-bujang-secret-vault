import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createResponder, getActiveDenials } from '../xdr/privilege/respond.mjs';
import { checkAccess } from '../xdr/privilege/check-access.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide as decideZtna } from '../src/decider.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json', import.meta.url), 'utf8'));
const now = Date.parse(fixture.alerts[0].timestamp) + 1000;
const { normal, suspicious } = fixtureRequests();
const requestAlert = { data: { url: '/api/notes/demo' } };
const binding = event => ({ agentName: event.agent.name, sourceAccount: event.data.srcuser,
  subjectId: normal.subjectId, classId: normal.classId, projectId: normal.projectId });
const fresh = event => ({ ...event, timestamp: new Date(now - 1000).toISOString() });
async function setup(t) {
  const directory = await mkdtemp(join(tmpdir(), 'privilege-respond-'));
  t.after(async () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  });
  const options = { rulesPath: join(directory, 'rules.json'), logPath: join(directory, 'alerts.log'), clock: () => now };
  return { options, respond: createResponder(options) };
}

test('replaying ambiguous and normal events never installs a denial; alerts append safely', async t => {
  const { options, respond } = await setup(t);
  await writeFile(options.logPath, '{"moduleKey":"persistence"}\n');
  for (const event of fixture.alerts.slice(9)) {
    const result = await respond(fresh(event), { binding: binding(event) });
    assert.equal(result.installed, 0);
    assert.equal((await checkAccess(normal, requestAlert, { now, rulesPath: options.rulesPath })).proceed, true);
  }
  await assert.rejects(readFile(options.rulesPath), { code: 'ENOENT' });
  const rows = (await readFile(options.logPath, 'utf8')).trimEnd().split('\n').map(JSON.parse);
  assert.equal(rows.length, 9);
  assert.equal(rows[0].moduleKey, 'persistence');
  assert.ok(rows.slice(1).every(row => row.action === 'alert'));
});

test('clear attacks deny only the bound subject and scope; replay never extends expiry', async t => {
  const { options, respond } = await setup(t);
  for (const event of fixture.alerts.slice(0, 9)) await respond(fresh(event), { binding: binding(event) });
  const before = await readFile(options.rulesPath, 'utf8');
  const rule = JSON.parse(before).rules[0];
  assert.equal(rule.action, 'deny');
  assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), 600000);
  assert.deepEqual([...rule.evidenceAlertIds].sort(), fixture.alerts.slice(0, 9).map(event => event.id));
  const context = { now, events: [], rulesPath: options.rulesPath };
  const access = await checkAccess(normal, requestAlert, context);
  assert.equal(access.proceed, false);
  assert.equal(access.privilegeDenyRules.length, 1);
  assert.deepEqual(access.ztna, await decideZtna(normal));
  for (const changes of [{ subjectId: 'other-subject' }, { projectId: 'other-project' }, { classId: 'other-class' }]) {
    assert.equal((await checkAccess({ ...normal, ...changes }, requestAlert, context)).proceed, true);
  }
  assert.equal((await checkAccess(normal, requestAlert, { ...context, now: now + 600000 })).proceed, true);
  assert.equal((await checkAccess(suspicious, requestAlert, { ...context, now: now + 600000 })).proceed, false);
  for (const event of fixture.alerts.slice(0, 9)) await respond(fresh(event), { binding: binding(event) });
  assert.equal(await readFile(options.rulesPath, 'utf8'), before);
  const log = await readFile(options.logPath, 'utf8');
  assert.equal(log.trimEnd().split('\n').length, 18);
  assert.doesNotMatch(log, /srcuser|srcip|user01|203\.0\.113\.11/u);
});

test('unverified account mappings, unsafe IDs, stale events and caller claims cannot install rules', async t => {
  const { options, respond } = await setup(t);
  const event = fresh(fixture.alerts[0]);
  for (const [alert, context] of [
    [event, {}],
    [event, { binding: { ...binding(event), sourceAccount: 'other-account' } }],
    [event, { binding: { ...binding(event), agentName: 'other-pc' } }],
    [{ ...event, id: 'Bearer synthetic-test' }, { binding: binding(event) }],
    [{ ...event, timestamp: new Date(now - 600000).toISOString() }, { binding: binding(event) }],
    [{ ...event, timestamp: new Date(now + 1).toISOString() }, { binding: binding(event) }],
    [{ ...fresh(fixture.alerts[18]), action: 'block', confidence: 1 }, { binding: binding(event) }],
  ]) assert.equal((await respond(alert, context)).installed, 0);
  assert.equal((await getActiveDenials(normal, options)).length, 0);
  await writeFile(options.rulesPath, 'invalid state');
  await assert.rejects(respond(event, { binding: binding(event) }), /privilege_rules_invalid/u);
  assert.equal(await readFile(options.rulesPath, 'utf8'), 'invalid state');
  assert.throws(() => createResponder({ ttlMs: 0 }), /invalid_rule_ttl/u);
});
