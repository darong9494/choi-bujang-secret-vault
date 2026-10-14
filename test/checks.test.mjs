import assert from 'node:assert/strict';
import { test } from 'node:test';
import handler from '../api/checks.js';
import opsHandler from '../api/ops.js';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { checkDecider } from '../scripts/decider-test.mjs';

test('작전실은 이번 HTTP 응답만 집계하고 실패한 재조회에 이전 성공을 쓰지 않는다', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  let unavailable = false;
  globalThis.fetch = async (url, options) => {
    calls.push({ url: new URL(url), options });
    if (unavailable) throw new Error('offline');
    const path = new URL(url).pathname;
    const status = path === '/' || path === '/api/checks' ? 200
      : path.startsWith('/api/restore/') ? 404 : 401;
    return new Response(path === '/api/checks' ? '{"ready":true}' : '{}', {
      status, headers: { 'x-vercel-id': `fixture-${calls.length}` },
    });
  };
  async function snapshot(api = handler) {
    let body;
    await api({ method: 'GET', query: {} }, {
      setHeader() {},
      status(value) { assert.equal(value, 200); return this; },
      json(value) { body = value; },
    });
    return body;
  }
  try {
    const first = await snapshot();
    assert.deepEqual(first.totals, { total: 17, blocked: 12, failed: 0, notRun: 5 });
    for (const key of ['total', 'blocked', 'failed', 'notRun']) {
      assert.equal(first[key], first.totals[key]);
    }
    assert.equal(calls.length, 12);
    assert.ok(calls.every(call => call.options.signal instanceof AbortSignal));
    assert.ok(calls.filter(call => call.url.pathname === '/api/checks')
      .every(call => call.url.searchParams.has('case')));
    assert.equal(first.checks.filter(check => check.source === '학생 판정기·탐지 가상 연습').length, 6);
    assert.ok(first.checks.filter(check => check.result === 'not_run')
      .every(check => check.observed === 'not_run'));
    for (const item of first.checks.filter(check => check.result !== 'not_run')) {
      assert.match(item.observed, /^HTTP \d{3}; bodyBytes=\d+(?:; jsonReady=(?:true|false))?$/u);
      assert.match(item.requestId, /^fixture-\d+$/u);
    }
    unavailable = true;
    const second = await snapshot();
    assert.deepEqual(second.totals, { total: 17, blocked: 0, failed: 0, notRun: 17 });
    for (const key of ['total', 'blocked', 'failed', 'notRun']) {
      assert.equal(second[key], second.totals[key]);
    }
    assert.equal(calls.length, 24);
    assert.equal(second.checks.filter(check => check.observed === 'network_error').length, 12);
    unavailable = false;
    const ops = await snapshot(opsHandler);
    assert.equal(ops.schema, 'aleph.ops.v1');
    assert.deepEqual(ops.summary, first.totals);
    assert.deepEqual(ops.items.map(item => item.observed), first.checks.map(item => item.observed));
    assert.notEqual(ops.items[0].requestId, first.checks[0].requestId);
    assert.equal(ops.items.length, ops.summary.total);
    assert.equal(ops.items.filter(item => item.kind === 'not_run').length, 5);
    assert.deepEqual(ops.rules.ids, RULE_IDS);
    assert.equal(ops.recovery.available, false);
    for (const item of ops.items) {
      if (item.kind === 'not_run') assert.equal(item.observed, 'not_run');
      else assert.match(item.observed, /^HTTP \d{3};/u);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('판정기는 계약에 있는 요청 이름만 읽고 등록된 규칙으로 응답한다', async () => {
  const names = new Set(['schema', 'requestId', 'classId', 'projectId', 'subjectId',
    'deviceId', 'service', 'method', 'path', 'route', 'queryLength', 'querySha256',
    'at', 'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals']);
  const results = await checkDecider({ ruleIds: RULE_IDS, decide: request => decide(new Proxy(request, {
    get(target, name) {
      assert.ok(names.has(name), `계약에 없는 요청 이름: ${String(name)}`);
      return target[name];
    },
  })) });
  assert.equal(results.length, 4);
  assert.ok(results.every(result => result.passed));
});

test('화면 수치는 API 합계와 같고 API 오류 뒤에 이전 수치를 남기지 않는다', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const source = html.slice(html.indexOf('    async function loadOps()'),
    html.indexOf('    opsRefresh.addEventListener'));
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { textContent: '', append() {}, replaceChildren() {} });
    return elements.get(id);
  };
  let fail = false;
  let mismatched = false;
  const context = {
    opsRefresh: {}, opsState: element('state'), checkRecords: element('records'),
    document: { querySelector: element, getElementById: id => element(`#${id}`), createElement: () => element(Symbol()) },
    fetch: async () => ({ ok: !fail, json: async () => ({
      schema: 'aleph.ops.v1', summary: { total: mismatched ? 99 : 3, blocked: 1, failed: 1, notRun: 1 },
      items: ['blocked', 'breached', 'not_run'].map(result => ({ result })), rules: { ids: [] }, recovery: {},
    }) }),
  };
  await runInNewContext(`${source}\nloadOps()`, context);
  assert.equal(element('#ops-total').textContent, '3');
  for (const id of ['blocked', 'failed', 'not-run']) assert.equal(element(`#ops-${id}`).textContent, '1');
  assert.match(html, /<dl id="ops-stats"/u);
  for (const key of ['total', 'blocked', 'failed', 'notRun']) {
    assert.ok(html.includes(`data-k="${key}"`));
  }
  mismatched = true;
  await runInNewContext('loadOps()', context);
  assert.equal(context.opsState.textContent, '화면 수치와 서버 기록이 일치하지 않습니다.');
  for (const id of ['total', 'blocked', 'failed', 'not-run']) assert.equal(element(`#ops-${id}`).textContent, '-');
  fail = true;
  await runInNewContext('loadOps()', context);
  for (const id of ['total', 'blocked', 'failed', 'not-run']) assert.equal(element(`#ops-${id}`).textContent, '-');
});
