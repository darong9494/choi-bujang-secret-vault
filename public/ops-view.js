const resultKey = { blocked: 'blocked', breached: 'failed', not_run: 'notRun' };
const sourceLabels = { operations: '서버 전용 운영 기록' };
const resultLabels = { blocked: '기대 응답', breached: '응답 불일치', not_run: '미실행 또는 응답 미확인' };

export function validateOpsRecord(data) {
  if (data?.schema !== 'aleph.ops.v1' || !Array.isArray(data.items)
      || !Array.isArray(data.rules?.ids) || data.rules.count !== data.rules.ids.length
      || !data.detection || !data.revocation || !data.recovery) throw new Error('서버 기록 형식이 맞지 않습니다.');
  if (data.source === 'not_connected') {
    if (data.status !== 'not_run' || data.checkedAt !== null || data.items.length !== 0
        || ['total', 'blocked', 'failed', 'notRun'].some(key => data.summary?.[key] !== null || data[key] !== null)) {
      throw new Error('미연결 운영 결과에 수치를 채울 수 없습니다.');
    }
    return data;
  }
  if (data.source !== 'operations' || data.status !== 'recorded') throw new Error('운영 기록 출처가 아닙니다.');
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
  const set = (name, value) => { root.querySelector(`[data-value="${name}"]`).textContent = value; };
  set('meta', `조회 시각 ${data.queriedAt} · 운영 기록 시각 ${data.checkedAt ?? '미제공'} · 배포 커밋 ${data.commit ?? '미제공'}`);
  set('rules', `구현된 규칙 ${data.rules.count}개 · ${data.rules.ids.join(', ')} · 운영 판정 결과 ${data.decision.status === 'not_run' ? '미실행' : '기록 있음'}`);
  set('detection', data.detection.reason);
  set('revocation', data.revocation.reason);
  set('recovery', data.recovery.verifiedVersion === null
    ? data.recovery.reason : `검증된 복구 버전 ${data.recovery.verifiedVersion}`);
  if (data.source === 'not_connected') {
    for (const dd of root.querySelectorAll('[data-k]')) dd.textContent = '미실행';
    return;
  }
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
    state.textContent = '서버의 운영 결과 연결 상태를 확인하는 중입니다.';
    try {
      const response = await fetch('/api/ops', { cache: 'no-store', signal: AbortSignal.timeout(10000) });
      if (!response.ok) throw new Error(`서버 기록을 읽지 못했습니다. HTTP ${response.status}`);
      const data = await response.json();
      if (current !== version) return;
      renderOps(root, data);
      state.textContent = data.source === 'not_connected'
        ? '운영 결과 조회 미연결입니다. 결과는 미실행으로 표시합니다.' : '서버 전용 운영 기록을 읽었습니다.';
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
