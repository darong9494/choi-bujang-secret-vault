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
    handlers: {}, append(...v) { this.children.push(...v); }, replaceChildren(...v) { this.children = v; },
    addEventListener(name, handler) { this.handlers[name] = handler; } });
  const numbers = ['total', 'recorded', 'notRun'].map(number => Object.assign(node(), { dataset: { number } }));
  const domains = Object.fromEntries(['decision', 'detection', 'revocation', 'recovery'].map(key => [key, node()]));
  const rows = node(), meta = node(), rules = node(), state = node(), refresh = node();
  const evidence = node(), comparison = node(), api = node();
  return { numbers, domains, rows, meta, rules, state, refresh, evidence, comparison, api,
    ownerDocument: { createElement: node },
    querySelectorAll: s => s === '[data-number]' ? numbers : Object.values(domains),
    querySelector(s) {
      return ({ '[data-rows]': rows, '[data-meta]': meta, '[data-rules]': rules,
        '[data-state]': state, '[data-refresh]': refresh, '[data-evidence]': evidence,
        '[data-comparison]': comparison, '[data-api]': api })[s] ?? domains[/data-domain="([a-z]+)"/u.exec(s)?.[1]];
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
  assert.match(ui.domains.recovery.textContent, /복구 정책 버전 4/u);
  assert.deepEqual(JSON.parse(ui.evidence.textContent), output.body);
  assert.deepEqual(output.body.domains.revocation, { status: 'not_run', recorded: 0, notRun: 1,
    latestOutcome: null, latestAt: null, policyRevision: null });
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
  assert.equal(ui.evidence.textContent, '');
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
    assert.ok(Object.values(ui.domains).every(n => n.textContent.includes('원본 조회 불가')));
    assert.deepEqual(JSON.parse(ui.evidence.textContent), output.body);
    assert.equal(ui.api.textContent, '이번 작전실 API 응답: HTTP 503');
  } finally { globalThis.fetch = original; }
});

test('POST는 원본 읽기를 실행하지 않고 거부한다', async () => {
  let called = false;
  const output = await invoke(createOperationsHandler({ readRecord: async () => { called = true; return fixture(); } }), { method: 'POST' });
  assert.equal(output.status, 405);
  assert.equal(called, false);
});

test('분야별 요약·복구 버전 변조도 전체 기록과 대조해 거부한다', () => {
  const data = projectRecord(fixture(), RULE_IDS);
  const ui = panel();
  renderSnapshot(ui, data);
  data.domains.recovery.policyRevision = 999;
  assert.throws(() => renderSnapshot(ui, data), /domain_summary_mismatch/u);
  assert.ok(ui.numbers.every(n => n.textContent === '—'));
  assert.equal(ui.evidence.textContent, '');
});

test('API는 한 번만 조회하고 그 응답에서 요약·행·가린 JSON을 표시한다', async () => {
  const response = await invoke(createOperationsHandler({ readRecord: async () => fixture() }));
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; return new Response(JSON.stringify(response.body), { status: 200 }); };
  try {
    const ui = panel();
    await mountOperations(ui);
    assert.equal(calls, 1);
    assert.deepEqual(JSON.parse(ui.evidence.textContent), response.body);
    assert.deepEqual(ui.numbers.map(n => n.textContent), ['4', '3', '1']);
  } finally { globalThis.fetch = original; }
});

test('늦게 도착한 과거 성공 응답이 최신 503 상태를 덮어쓰지 않는다', async () => {
  const old = projectRecord(fixture(), RULE_IDS);
  const unavailable = (await invoke(ops)).body;
  const original = globalThis.fetch;
  let resolveOld;
  let calls = 0;
  globalThis.fetch = () => ++calls === 1 ? new Promise(resolve => { resolveOld = resolve; })
    : Promise.resolve(new Response(JSON.stringify(unavailable), { status: 503 }));
  try {
    const ui = panel();
    const first = mountOperations(ui);
    await ui.refresh.handlers.click();
    resolveOld(new Response(JSON.stringify(old), { status: 200 }));
    await first;
    assert.deepEqual(JSON.parse(ui.evidence.textContent), unavailable);
    assert.ok(ui.numbers.every(n => n.textContent === '—'));
    assert.equal(ui.api.textContent, '이번 작전실 API 응답: HTTP 503');
  } finally { globalThis.fetch = original; }
});

test('503 응답에 없는 운영 수치나 버전을 채워 넣으면 화면에서 거부한다', async () => {
  const response = (await invoke(ops)).body;
  response.domains.detection.recorded = 0;
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify(response), { status: 503 });
  try {
    const ui = panel();
    await mountOperations(ui);
    assert.ok(ui.numbers.every(n => n.textContent === '—'));
    assert.equal(ui.evidence.textContent, '');
    assert.match(ui.state.textContent, /대조에 실패/u);
  } finally { globalThis.fetch = original; }
});
