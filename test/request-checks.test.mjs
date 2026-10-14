import assert from 'node:assert/strict';
import { test } from 'node:test';
import { collectRequestChecks } from '../src/request-checks.mjs';
import { createRequestChecksHandler } from '../src/request-checks-service.mjs';
import { renderMeasurements, validateMeasurements, mountMeasurements } from '../public/request-checks-view.js';

const config = { publicAppUrl: 'https://fixture.vercel.app/', originalApiUrl: 'https://fixture.supabase.co/rest/v1/notes' };
const ownId = '11111111-1111-4111-8111-111111111111';
const marker = 'PRIVATE_NOTE_AND_ACCOUNT_MUST_NOT_APPEAR';
const authorization = 'Bearer fixture-session';

function fakeFetch(calls, { approved = true, offline = false, leak = false } = {}) {
  return async (url, options) => {
    const u = new URL(url);
    calls.push({ u, options });
    if (offline) throw new Error(marker);
    const auth = options.headers.Authorization === authorization;
    let status = 401, body = {};
    if (u.pathname === '/') { status = 200; body = { page: true }; }
    else if (u.pathname === '/data.json') { status = 200; body = { notes: [] }; }
    else if (u.pathname.startsWith('/api/restore/')) status = 404;
    else if (u.pathname === '/api/device/status' && auth) { status = 200; body = { approved }; }
    else if (u.pathname === '/api/notes' && auth && options.headers['X-Resource-Id'] === 'memo:collection') {
      status = 200; body = [{ id: ownId, body: marker, title: marker }];
    } else if (u.pathname === `/api/notes/${ownId}` && auth && options.headers['X-Resource-Id'] === `memo:${ownId}`) {
      status = 200; body = { id: ownId, body: marker, title: marker };
    }
    if (leak && status === 401) body = { body: marker };
    const receiptHeader = u.hostname.endsWith('.supabase.co') ? 'sb-request-id' : 'x-vercel-id';
    return new Response(JSON.stringify(body), { status, headers: { [receiptHeader]: `test-receipt-${calls.length}` } });
  };
}

function panel() {
  const node = () => ({ textContent: '', children: [], disabled: false, handlers: {},
    append(...v) { this.children.push(...v); }, replaceChildren(...v) { this.children = v; },
    addEventListener(name, handler) { this.handlers[name] = handler; } });
  const nodes = Object.fromEntries(['rows', 'summary', 'confirmation', 'state'].map(k => [k, node()]));
  const button = node(), save = node();
  return { ...nodes, button, save, ownerDocument: { createElement: node }, querySelector(selector) {
    if (selector === '[data-run-measurements]') return button;
    if (selector === '[data-save-measurements]') return save;
    return nodes[/data-measurement-([a-z]+)/u.exec(selector)[1]];
  } };
}

test('정상 보호자료 200과 금지 요청 401의 모의 응답을 영수증으로 구분해 기록한다', async () => {
  const original = globalThis.fetch, calls = [];
  globalThis.fetch = fakeFetch(calls);
  try {
    const data = await collectRequestChecks(config, { authorization });
    validateMeasurements(data);
    assert.deepEqual(data.summary, { total: 18, matched: 10, mismatch: 0, inconclusive: 1, notRun: 7, networkError: 0 });
    assert.equal(data.confirmation.requiredPairMeasured, true);
    assert.equal(data.confirmation.complete, false);
    assert.equal(calls.length, 11);
    assert.ok(calls.every(c => c.options.method === 'GET'));
    assert.deepEqual([...new Set(data.rows.map(r => r.stage))], [1,2,3,4,5,6,7,8,9,10,11]);
    for (const row of data.rows.filter(r => r.httpStatus !== null)) {
      assert.match(row.requestId, /^test-receipt-/u);
      assert.ok(Number.isFinite(Date.parse(row.checkedAt)));
    }
    assert.ok(data.rows.some(r => r.kind === 'normal_protected' && r.result === 'matched' && r.httpStatus === 200));
    assert.ok(data.rows.some(r => r.kind === 'forbidden' && r.result === 'matched' && r.httpStatus === 401));
    assert.equal(data.rows.find(r => r.id === 'anonymous_restore').result, 'inconclusive');
    const thirdParty = calls.find(c => c.u.hostname.endsWith('.supabase.co'));
    assert.equal(thirdParty.options.headers.Authorization, undefined);
    assert.ok(!JSON.stringify(data).includes(marker));
    assert.ok(!JSON.stringify(data).includes(ownId));
    assert.ok(!JSON.stringify(data).includes(authorization));
    assert.deepEqual(data.finalAssault, { status: 'not_run', expectedCases: 41, measuredCases: null });
    const ui = panel();
    renderMeasurements(ui, data);
    assert.equal(ui.rows.children.length, data.summary.total);
    assert.match(ui.confirmation.textContent, /두 결과 모두 확인/u);
    assert.match(ui.confirmation.textContent, /전체 확인: 미완료/u);
  } finally { globalThis.fetch = original; }
});

test('공개 화면 200이나 기기 상태 200으로 정상 보호자료 허용을 대신하지 않는다', async () => {
  const original = globalThis.fetch, calls = [];
  globalThis.fetch = fakeFetch(calls, { approved: false });
  try {
    const data = await collectRequestChecks(config, { authorization });
    validateMeasurements(data);
    assert.equal(data.confirmation.normalProtectedAllowed, false);
    assert.equal(data.confirmation.requiredPairMeasured, false);
    assert.equal(data.rows.find(r => r.id === 'normal_device_status').httpStatus, 200);
    const normal = data.rows.find(r => r.id === 'normal_owned_list');
    assert.equal(normal.result, 'not_run');
    assert.equal(normal.checkedAt, null);
    assert.equal(normal.requestId, null);
    assert.ok(!calls.some(c => c.u.pathname === '/api/notes' && c.options.headers.Authorization === authorization));
    const anonymous = await collectRequestChecks(config);
    assert.equal(anonymous.confirmation.requiredPairMeasured, false);
    assert.equal(anonymous.rows.find(r => r.id === 'normal_owned_list').reason, 'login_required');
  } finally { globalThis.fetch = original; }
});

test('응답 미확인과 미실행을 구분하고 41종 시험을 실행·통과로 채우지 않는다', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = fakeFetch([], { offline: true });
  try {
    const data = await collectRequestChecks(config);
    validateMeasurements(data);
    assert.equal(data.summary.networkError, 8);
    assert.equal(data.summary.notRun, 10);
    assert.equal(data.summary.matched, 0);
    assert.equal(data.finalAssault.measuredCases, null);
    assert.ok(data.rows.filter(r => r.result === 'network_error').every(r => r.attemptedAt && r.checkedAt === null));
    assert.ok(data.rows.filter(r => r.result === 'not_run').every(r => r.attemptedAt === null));
  } finally { globalThis.fetch = original; }
});

test('401 응답에 메모가 섞이면 거부 성공으로 표시하지 않으며 본문을 공개하지 않는다', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = fakeFetch([], { leak: true });
  try {
    const data = await collectRequestChecks(config);
    assert.equal(data.rows.find(r => r.id === 'anonymous_notes').result, 'mismatch');
    assert.ok(!JSON.stringify(data).includes(marker));
  } finally { globalThis.fetch = original; }
});

test('합계나 정상 허용 확인 문구를 조작하면 표와 수치를 비운다', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = fakeFetch([]);
  try {
    const data = await collectRequestChecks(config);
    const ui = panel();
    renderMeasurements(ui, data);
    data.confirmation.requiredPairMeasured = true;
    assert.throws(() => renderMeasurements(ui, data), /confirmation_mismatch/u);
    assert.equal(ui.rows.children.length, 0);
    const altered = await collectRequestChecks(config);
    altered.summary.matched++;
    assert.throws(() => renderMeasurements(ui, altered), /summary_mismatch/u);
  } finally { globalThis.fetch = original; }
});

test('API는 잘못된 로그인·GET을 거부하고 외부 요청을 보내지 않는다', async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; throw new Error('should_not_fetch'); };
  async function invoke(req) {
    let code;
    await createRequestChecksHandler({ config, verifyIdentity: async () => null })(req, {
      setHeader() {}, status(s) { code = s; return this; }, json() {},
    });
    return code;
  }
  try {
    assert.equal(await invoke({ method: 'GET' }), 405);
    assert.equal(await invoke({ method: 'POST', headers: { authorization } }), 401);
    assert.equal(calls, 0);
  } finally { globalThis.fetch = original; }
});

test('세션이 바뀌면 늦게 온 실측 응답을 표시하지 않는다', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = fakeFetch([]);
  const data = await collectRequestChecks(config);
  let resolve;
  globalThis.fetch = () => new Promise(done => { resolve = done; });
  try {
    const ui = panel();
    const reset = mountMeasurements(ui);
    const pending = ui.button.handlers.click();
    reset();
    resolve(new Response(JSON.stringify(data), { status: 200 }));
    await pending;
    assert.equal(ui.rows.children.length, 0);
    assert.match(ui.state.textContent, /이전 세션/u);
    assert.equal(ui.button.disabled, false);
  } finally { globalThis.fetch = original; }
});
