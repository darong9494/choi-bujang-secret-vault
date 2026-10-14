import assert from 'node:assert/strict';
import { test } from 'node:test';
import handler from '../api/ops.js';
import { operationsSnapshot } from '../src/operations.mjs';
import { renderOps, mountOps } from '../public/ops-view.js';
import { RULE_IDS } from '../src/decider.mjs';

function panel() {
  const node = () => ({ textContent: '', children: [], disabled: false,
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; }, addEventListener() {} });
  const counts = ['total', 'blocked', 'failed', 'notRun'].map(k => Object.assign(node(), { dataset: { k } }));
  const fields = Object.fromEntries(['meta', 'rules', 'detection', 'revocation', 'recovery'].map(k => [k, node()]));
  const rows = node(), button = node(), state = node();
  return { counts, fields, rows, button, state, ownerDocument: { createElement: node },
    querySelectorAll: selector => selector === '[data-k]' ? counts : Object.values(fields),
    querySelector(selector) {
      if (selector === '[data-rows]') return rows;
      if (selector === '[data-refresh]') return button;
      if (selector === '[data-state]') return state;
      return fields[/data-value="([a-z]+)"/u.exec(selector)[1]];
    } };
}

function recorded() {
  const checkedAt = '2026-10-14T00:00:00.000Z';
  return { source: 'operations', checkedAt,
    summary: { total: 2, blocked: 1, failed: 0, notRun: 1 },
    items: [
      { attackId: 'decision_receipt', category: 'decision', stage: 12, checkedAt, httpStatus: 403, result: 'blocked' },
      { attackId: 'revocation_pending', category: 'revocation', stage: 9, result: 'not_run' },
    ] };
}

test('운영 미연결 API는 자기 점검을 실행하거나 없는 수치를 0으로 채우지 않는다', async () => {
  const fetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('must_not_probe_self_checks'); };
  try {
    let body;
    await handler({ method: 'GET' }, { setHeader() {}, status(s) { assert.equal(s, 200); return this; }, json(v) { body = v; } });
    assert.equal(body.source, 'not_connected');
    assert.equal(body.status, 'not_run');
    assert.deepEqual(body.rules.ids, RULE_IDS);
    assert.equal(body.rules.count, RULE_IDS.length);
    assert.equal(body.checkedAt, null);
    assert.deepEqual(body.items, []);
    assert.ok(Object.values(body.summary).every(v => v === null));
    const ui = panel();
    renderOps(ui, body);
    assert.ok(ui.counts.every(n => n.textContent === '미실행'));
    assert.equal(ui.rows.children.length, 0);
    for (const key of ['detection', 'revocation', 'recovery']) assert.match(ui.fields[key].textContent, /미실행/u);
  } finally { globalThis.fetch = fetch; }
});

test('구현 규칙 수를 운영 성공으로 세지 않고 서버 기록과 같은 응답에서 집계한다', () => {
  const ui = panel();
  const snapshot = operationsSnapshot(recorded());
  renderOps(ui, snapshot);
  assert.deepEqual(ui.counts.map(n => n.textContent), ['2', '1', '0', '1']);
  assert.equal(ui.rows.children.length, 2);
  assert.match(ui.fields.rules.textContent, new RegExp(`구현된 규칙 ${RULE_IDS.length}개`, 'u'));
  const changed = structuredClone(snapshot);
  changed.summary.blocked = 4;
  assert.throws(() => renderOps(ui, changed), /수치와 서버 기록/u);
  assert.ok(ui.counts.every(n => n.textContent === '-'));
  assert.equal(ui.rows.children.length, 0);
  renderOps(ui, operationsSnapshot());
  assert.ok(ui.counts.every(n => n.textContent === '미실행'));
});

test('미연결에 숫자 채우기, 가상 연습 승격, 잘못된 서버 합계를 거부한다', () => {
  const ui = panel();
  const fake = operationsSnapshot();
  fake.summary.total = 0;
  fake.total = 0;
  assert.throws(() => renderOps(ui, fake), /미연결/u);
  const fixture = recorded();
  fixture.source = 'student_fixture';
  assert.throws(() => operationsSnapshot(fixture), /invalid_operations_record/u);
  const mismatch = recorded();
  mismatch.summary.blocked++;
  assert.throws(() => operationsSnapshot(mismatch), /summary_mismatch/u);
  const missing = recorded();
  missing.items[0].httpStatus = null;
  assert.throws(() => operationsSnapshot(missing), /missing_operation_receipt/u);
});

test('서버 전용 기록의 본문·계정·기기·토큰과 추가 필드는 가려서 반환한다', () => {
  const input = recorded();
  const canary = 'PRIVATE_CONTENT_MUST_NOT_APPEAR';
  input.token = canary;
  Object.assign(input.items[0], { body: canary, subjectId: canary, deviceId: canary, expected: canary, observed: canary });
  assert.ok(!JSON.stringify(operationsSnapshot(input)).includes(canary));
});

test('조회 실패 후 이전 운영 숫자와 기록을 지운다', async () => {
  const ui = panel();
  renderOps(ui, operationsSnapshot(recorded()));
  const fetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('offline'); };
  try {
    await mountOps(ui);
    assert.ok(ui.counts.every(n => n.textContent === '-'));
    assert.equal(ui.rows.children.length, 0);
    assert.equal(ui.button.disabled, false);
  } finally { globalThis.fetch = fetch; }
});
