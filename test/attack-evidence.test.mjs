import test from 'node:test';
import assert from 'node:assert/strict';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = { step: 12, publicAppUrl: 'https://vault.vercel.app/' };

test('submission observations match independently observable requests and case IDs', async t => {
  const calls = [];
  const statuses = [200, 401, 404, 401];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url, options });
    return new Response(null, { status: statuses[calls.length - 1] });
  });
  const attempts = await runAttackChecks(config);
  assert.equal(attempts.length, 10);
  assert.equal(calls.length, 4);
  for (const [index, call] of calls.entries()) {
    const evidence = call.options.alephEvidence;
    assert.equal(evidence.requestKey, 'read');
    const matching = attempts.filter(row => row.attackId === evidence.caseId);
    assert.equal(matching.length, 1);
    assert.equal(matching[0].observed, `HTTP ${statuses[index]}`);
    assert.equal(call.url.search, '');
    assert.equal(call.options.headers, undefined);
    assert.equal(call.options.method ?? 'GET', 'GET');
  }
  const requested = new Set(calls.map(call => call.options.alephEvidence.caseId));
  const notRun = attempts.filter(row => !requested.has(row.attackId));
  assert.equal(notRun.length, 6);
  assert.ok(notRun.every(row => row.observed === 'not_run'));
  assert.ok(attempts.every(row => Object.keys(row).sort().join(',') === 'attackId,expected,observed'));
  const restore = attempts.find(row => row.attackId === 'anonymous_note_restore');
  assert.equal(restore.observed, 'HTTP 404');
  assert.match(restore.expected, /404는 확인 불가/u);
});

test('unexpected response statuses are recorded without inventing a successful result', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 503 }));
  const attempts = await runAttackChecks(config);
  assert.equal(attempts.filter(row => row.observed === 'HTTP 503').length, 4);
  assert.equal(attempts.filter(row => row.observed === 'not_run').length, 6);
});

test('network failures never become an HTTP success observation', async t => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('offline'); });
  const attempts = await runAttackChecks(config);
  assert.equal(attempts.filter(row => row.observed === 'network_error').length, 4);
  assert.equal(attempts.filter(row => row.observed === 'not_run').length, 6);
});
