import assert from 'node:assert/strict';
import { test } from 'node:test';
import ops from '../api/ops.js';
import { createOperationsHandler } from '../src/operations-service.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import { projectRecord } from '../public/ops-contract.js';
import { renderSnapshot, mountOperations } from '../public/ops-view.js';

async function invoke(handler, req = { method: 'GET' }) {
  const output = { headers: {} };
  await handler(req, {
    setHeader(k, v) { output.headers[k.toLowerCase()] = v; },
    status(v) { output.status = v; return this; }, json(v) { output.body = v; },
  });
  return output;
}

function fixture() {
  const at = '2026-10-14T00:00:00.000Z';
  return { schema: 'aleph.operations-record.v1', source: 'server_record', checkedAt: at,
    summary: { total: 4, recorded: 3, notRun: 1 }, records: [
      { category: 'decision', status: 'recorded', outcome: 'deny', at, ruleIds: [RULE_IDS[0]] },
      { category: 'detection', status: 'recorded', outcome: 'propose_revocation', at },
      { category: 'revocation', status: 'not_run' },
      { category: 'recovery', status: 'recorded', outcome: 'restored', at, policyRevision: 4 },
    ] };
}

function panel() {
  const node = () => ({ textContent: '', children: [], disabled: false,
    append(...v) { this.children.push(...v); }, replaceChildren(...v) { this.children = v; }, addEventListener() {} });
  const numbers = ['total', 'recorded', 'notRun'].map(number => Object.assign(node(), { dataset: { number } }));
  const domains = Object.fromEntries(['decision', 'detection', 'revocation', 'recovery'].map(key => [key, node()]));
  const rows = node(), meta = node(), rules = node(), state = node(), refresh = node();
  return { numbers, domains, rows, meta, rules, state, refresh, ownerDocument: { createElement: node },
    querySelectorAll: s => s === '[data-number]' ? numbers : Object.values(domains),
    querySelector(s) {
      return ({ '[data-rows]': rows, '[data-meta]': meta, '[data-rules]': rules,
        '[data-state]': state, '[data-refresh]': refresh })[s] ?? domains[/data-domain="([a-z]+)"/u.exec(s)?.[1]];
    } };
}

test('원본이 없으면 503이며 숫자·빈 운영 결과·가상 결과를 만들지 않는다', async () => {
  const output = await invoke(ops, { method: 'GET', body: fixture(), query: { source: 'server_record' } });
  assert.equal(output.status, 503);
  assert.equal(output.body.error, 'operations_source_not_connected');
  assert.equal(output.headers['cache-control'], 'no-store');
  assert.equal(output.body.summary, undefined);
  assert.equal(output.body.records, undefined);
  assert.deepEqual(output.body.rules.ids, RULE_IDS);
});

test('서버 원본·가린 응답·화면 합계가 같은 행을 기준으로 일치한다', async () => {
  const raw = fixture();
  const output = await invoke(createOperationsHandler({ readRecord: async () => raw }));
  assert.equal(output.status, 200);
  assert.deepEqual(output.body.summary, raw.summary);
  const ui = panel();
  renderSnapshot(ui, output.body);
  assert.deepEqual(ui.numbers.map(n => n.textContent), ['4', '3', '1']);
  assert.equal(ui.rows.children.length, 4);
  assert.match(ui.domains.revocation.textContent, /미실행 1건/u);
  assert.match(ui.domains.detection.textContent, /회수 제안/u);
  assert.equal(ui.rows.children[3].children[4].textContent, '4');
});

test('서버 원본 합계 불일치는 503, 화면 응답 변조는 숫자와 행 삭제', async () => {
  const raw = fixture();
  raw.summary.recorded = 10;
  const output = await invoke(createOperationsHandler({ readRecord: async () => raw }));
  assert.equal(output.status, 503);
  assert.equal(output.body.summary, undefined);
  const ui = panel();
  const valid = projectRecord(fixture(), RULE_IDS);
  renderSnapshot(ui, valid);
  const altered = structuredClone(valid);
  altered.summary.total++;
  assert.throws(() => renderSnapshot(ui, altered), /summary_mismatch/u);
  assert.ok(ui.numbers.every(n => n.textContent === '—'));
  assert.equal(ui.rows.children.length, 0);
});

test('가상 출처·불완전 실행 결과·미실행에 섞인 결과는 거부한다', () => {
  const exercise = fixture();
  exercise.source = 'student_fixture';
  assert.throws(() => projectRecord(exercise, RULE_IDS), /invalid_source/u);
  const missing = fixture();
  missing.records[0].at = null;
  assert.throws(() => projectRecord(missing, RULE_IDS), /missing_actual/u);
  const mixed = fixture();
  mixed.records[2].outcome = 'revoked';
  assert.throws(() => projectRecord(mixed, RULE_IDS), /unrun_has/u);
});

test('메모 본문·계정·기기·비밀값·추가 집계 필드는 공개하지 않는다', async () => {
  const raw = fixture();
  const marker = 'PRIVATE_CONTENT_MUST_NOT_APPEAR';
  raw.secret = marker;
  raw.summary.extra = marker;
  Object.assign(raw.records[0], { body: marker, subjectId: marker, deviceId: marker, token: marker });
  const output = await invoke(createOperationsHandler({ readRecord: async () => raw }));
  assert.equal(output.status, 200);
  assert.ok(!JSON.stringify(output.body).includes(marker));
  const broken = await invoke(createOperationsHandler({ readRecord: async () => { throw new Error(marker); } }));
  assert.ok(!JSON.stringify(broken.body).includes(marker));
});

test('재조회 503에서 이전 운영 결과를 지우고 구현 규칙만 유지한다', async () => {
  const ui = panel();
  renderSnapshot(ui, projectRecord(fixture(), RULE_IDS));
  const output = await invoke(ops);
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify(output.body), { status: output.status });
  try {
    await mountOperations(ui);
    assert.ok(ui.numbers.every(n => n.textContent === '—'));
    assert.equal(ui.rows.children.length, 0);
    assert.match(ui.state.textContent, /원본 미연결/u);
    assert.match(ui.rules.textContent, new RegExp(`구현된 규칙 ${RULE_IDS.length}개`, 'u'));
    assert.ok(Object.values(ui.domains).every(n => n.textContent === '결과 원본 미확인'));
  } finally { globalThis.fetch = original; }
});

test('POST는 원본 읽기를 실행하지 않고 거부한다', async () => {
  let called = false;
  const output = await invoke(createOperationsHandler({ readRecord: async () => { called = true; return fixture(); } }), { method: 'POST' });
  assert.equal(output.status, 405);
  assert.equal(called, false);
});
