const resultKey = { blocked: 'blocked', breached: 'failed', not_run: 'notRun' };
const sourceLabels = { live_api: '배포 API 실측', fixture_api: '학생 코드 가상 연습 API', not_run: '미실행' };
const resultLabels = { blocked: '기대 응답', breached: '응답 불일치', not_run: '미실행 또는 응답 미확인' };

export function validateOpsRecord(data) {
  if (data?.schema !== 'aleph.ops.v1' || !Array.isArray(data.items)
      || !Array.isArray(data.rules?.ids) || data.rules.count !== data.rules.ids.length
      || !data.detection || !data.revocation || !data.recovery) throw new Error('서버 기록 형식이 맞지 않습니다.');
  const counts = { total: data.items.length, blocked: 0, failed: 0, notRun: 0 };
  const ids = new Set();
  for (const item of data.items) {
    if (typeof item.attackId !== 'string' || ids.has(item.attackId)
        || !Object.hasOwn(resultKey, item.result) || !Object.hasOwn(sourceLabels, item.kind)) {
      throw new Error('점검 항목이 중복되거나 형식이 맞지 않습니다.');
    }
    ids.add(item.attackId);
    if (item.result === 'not_run') {
      if (!['not_run', 'network_error'].includes(item.observed) || item.httpStatus !== null
          || item.requestId !== null) throw new Error('미실행 기록에 실행 결과가 섞였습니다.');
    } else {
      const status = /^HTTP (\d{3})(?:;|$)/u.exec(item.observed);
      if (item.kind === 'not_run' || !status || Number(status[1]) !== item.httpStatus) {
        throw new Error('실제 HTTP 응답 기록이 없습니다.');
      }
    }
    counts[resultKey[item.result]]++;
  }
  if (Object.keys(counts).some(key => !Number.isInteger(data.summary?.[key])
      || data.summary[key] !== counts[key] || data[key] !== counts[key])) {
    throw new Error('화면 수치와 서버 기록이 일치하지 않습니다.');
  }
  return data;
}

export function clearOps(root) {
  for (const dd of root.querySelectorAll('[data-k]')) dd.textContent = '-';
  for (const field of root.querySelectorAll('[data-value]')) field.textContent = '';
  root.querySelector('[data-rows]').replaceChildren();
}

export function renderOps(root, input) {
  // Clear first, including when a malformed refresh follows a previously valid record.
  clearOps(root);
  const data = validateOpsRecord(input);
  const doc = root.ownerDocument;
  const rows = data.items.map(item => {
    const row = doc.createElement('tr');
    const actual = item.observed + (item.outcome?.decision ? ` · ${item.outcome.decision}` : '')
      + (item.outcome?.action ? ` · ${item.outcome.action} (${item.outcome.eventCount}건)` : '');
    for (const value of [item.stage, item.attackId, sourceLabels[item.kind], item.expected,
      actual, item.requestId ?? '미제공', item.checkedAt ?? '미실행', resultLabels[item.result]]) {
      const cell = doc.createElement('td');
      cell.textContent = String(value);
      row.append(cell);
    }
    return row;
  });
  const set = (name, value) => { root.querySelector(`[data-value="${name}"]`).textContent = value; };
  set('meta', `수집 완료 ${data.checkedAt} · 배포 커밋 ${data.commit ?? '미제공'}`);
  set('rules', `${data.rules.count}개 · ${data.rules.ids.join(', ')}`);
  const detections = data.items.filter(item => data.detection.cases.includes(item.attackId));
  set('detection', detections.map(item => `${item.expected}: ${item.outcome?.action ?? '결과 미확인'}`
    + ` · ${item.outcome?.eventCount ?? '-'}건 · ${item.observed}`).join(' / ')
    + ' · 운영 사건 전달은 미실행');
  set('revocation', data.revocation.reason);
  set('recovery', data.recovery.verifiedVersion === null
    ? `검증된 복구 버전 미확인 · ${data.recovery.reason}` : `검증된 복구 버전 ${data.recovery.verifiedVersion}`);
  root.querySelector('[data-rows]').replaceChildren(...rows);
  // Display the server's summary; the independently counted rows only validate it.
  for (const dd of root.querySelectorAll('[data-k]')) dd.textContent = String(data.summary[dd.dataset.k]);
}

export function mountOps(root) {
  const button = root.querySelector('[data-refresh]');
  const state = root.querySelector('[data-state]');
  let version = 0;
  async function load() {
    const current = ++version;
    button.disabled = true;
    clearOps(root);
    state.textContent = '서버가 실제 점검 응답을 수집하는 중입니다.';
    try {
      const response = await fetch('/api/ops', { cache: 'no-store', signal: AbortSignal.timeout(10000) });
      if (!response.ok) throw new Error(`서버 기록을 읽지 못했습니다. HTTP ${response.status}`);
      const data = await response.json();
      if (current !== version) return;
      renderOps(root, data);
      state.textContent = '이번 서버 응답의 기록입니다. 학생 자기 점검이며 심판 판정이 아닙니다.';
    } catch (error) {
      if (current !== version) return;
      clearOps(root);
      state.textContent = error instanceof Error ? error.message : '서버 기록을 읽지 못했습니다.';
    } finally {
      if (current === version) button.disabled = false;
    }
  }
  button.addEventListener('click', load);
  return load();
}

if (typeof document !== 'undefined') {
  for (const root of document.querySelectorAll('[data-ops]')) void mountOps(root);
}
