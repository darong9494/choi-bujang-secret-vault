import assert from 'node:assert/strict';
import { test } from 'node:test';
import ops from '../api/ops.js';
import checks from '../api/checks.js';
import { runAttackChecks } from '../src/attack-check.mjs';
import { renderOps, mountOps } from '../public/ops-view.js';

const config = { step: 12, publicAppUrl: 'https://fixture.vercel.app/' };
const canary = 'NOTE_BODY_MUST_NEVER_BE_PUBLISHED';

async function call(handler, req = { method: 'GET', query: {} }) {
  const result = { headers: {} };
  await handler(req, {
    setHeader(k, v) { result.headers[k.toLowerCase()] = v; },
    status(v) { result.status = v; return this; },
    json(v) { result.body = v; },
  });
  return result;
}

function panel() {
  const node = () => ({ textContent: '', children: [], disabled: false,
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; }, addEventListener() {} });
  const counts = ['total', 'blocked', 'failed', 'notRun'].map(k => Object.assign(node(), { dataset: { k } }));
  const fields = Object.fromEntries(['meta', 'rules', 'detection', 'revocation', 'recovery'].map(k => [k, node()]));
  const rows = node(), button = node(), state = node();
  return {
    counts, fields, rows, button, state,
    ownerDocument: { createElement: node },
    querySelectorAll(selector) { return selector === '[data-k]' ? counts : Object.values(fields); },
    querySelector(selector) {
      if (selector === '[data-rows]') return rows;
      if (selector === '[data-refresh]') return button;
      if (selector === '[data-state]') return state;
      return fields[/data-value="([a-z]+)"/u.exec(selector)[1]];
    },
  };
}

test('API·화면·제출 기록 일치, 응답 누락·불일치·본문 노출 방지', async () => {
  const original = globalThis.fetch;
  const calls = [];
  let mode = 'normal';
  globalThis.fetch = async (url, options) => {
    const u = new URL(url);
    calls.push({ u, options });
    if (mode === 'offline') throw new Error(canary);
    if (u.pathname === '/api/checks') {
      const result = await call(checks, { method: 'GET', query: { case: u.searchParams.get('case') } });
      return new Response(JSON.stringify(result.body), { status: result.status });
    }
    const status = u.pathname === '/' ? 200 : u.pathname.startsWith('/api/restore/') ? 404
      : mode === 'leak' && u.pathname === '/api/notes' ? 200 : 401;
    return new Response(JSON.stringify({ body: canary }), {
      status, headers: { 'x-vercel-id': `fixture-${calls.length}` },
    });
  };
  // The normal fake denial has no body field, like the protected production API.
  const wrapped = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    const response = await wrapped(url, options);
    if (mode === 'normal' && response.status !== 200) return new Response('{}', { status: response.status });
    return response;
  };
  try {
    const first = await call(ops);
    assert.equal(first.status, 200);
    assert.equal(first.headers['cache-control'], 'no-store');
    assert.equal(calls.length, 12);
    const record = first.body;
    assert.deepEqual(record.summary, { total: 17, blocked: 12, failed: 0, notRun: 5 });
    assert.equal(record.items.length, 17);
    assert.equal(new Set(calls.map(c => c.options.alephEvidence.caseId)).size, 12);
    assert.ok(calls.every(c => c.options.alephEvidence.requestKey === 'read'));
    assert.equal(record.items.filter(i => i.kind === 'fixture_api').length, 6);
    assert.deepEqual(record.items.find(i => i.attackId === 'normal_read_detection').outcome,
      { action: 'observe', eventCount: 30 });
    assert.deepEqual(record.items.find(i => i.attackId === 'burst_read_detection').outcome,
      { action: 'propose_revocation', eventCount: 121 });
    assert.ok(!JSON.stringify(record).includes(canary));
    assert.equal(record.revocation.status, 'not_run');
    assert.equal(record.recovery.verifiedVersion, null);
    for (const key of Object.keys(record.summary)) assert.equal(record[key], record.summary[key]);
    const ui = panel();
    renderOps(ui, record);
    assert.deepEqual(ui.counts.map(n => n.textContent), ['17', '12', '0', '5']);
    assert.equal(ui.rows.children.length, 17);
    const attempts = await runAttackChecks(config);
    assert.deepEqual(attempts, record.items.map(({ attackId, stage, expected, observed, result }) =>
      ({ attackId, stage, expected, observed, result })));
    assert.ok(attempts.every(a => Object.keys(a).sort().join(',') === 'attackId,expected,observed,result,stage'));
    const inconsistent = structuredClone(record);
    inconsistent.summary.blocked++;
    assert.throws(() => renderOps(ui, inconsistent), /수치와 서버 기록/u);
    assert.ok(ui.counts.every(n => n.textContent === '-'));
    assert.equal(ui.rows.children.length, 0);
    renderOps(ui, record);
    globalThis.fetch = async () => { throw new Error('offline'); };
    await mountOps(ui);
    assert.ok(ui.counts.every(n => n.textContent === '-'));
    assert.equal(ui.rows.children.length, 0);
    assert.equal(ui.button.disabled, false);
    globalThis.fetch = wrapped;
    mode = 'leak';
    const leaked = (await call(ops)).body;
    assert.ok(leaked.summary.failed > 0);
    assert.ok(!JSON.stringify(leaked).includes(canary));
    mode = 'offline';
    const offline = (await call(ops)).body;
    assert.deepEqual(offline.summary, { total: 17, blocked: 0, failed: 0, notRun: 17 });
    assert.equal(offline.items.filter(i => i.observed === 'network_error').length, 12);
    assert.equal(offline.items.filter(i => i.observed === 'not_run').length, 5);
    assert.ok(!JSON.stringify(offline).includes(canary));
    const before = calls.length;
    assert.equal((await call(ops, { method: 'POST' })).status, 405);
    assert.equal((await call(checks, { method: 'GET', query: { case: ['x'] } })).status, 400);
    assert.equal(calls.length, before);
  } finally {
    globalThis.fetch = original;
  }
});
