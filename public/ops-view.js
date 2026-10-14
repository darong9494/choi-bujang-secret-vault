import { CATEGORIES, validateSnapshot, validateUnavailable, maskedEvidence } from './ops-contract.js';

const labels = { decision: '판정', detection: '탐지', revocation: '회수', recovery: '복구' };
const outcomes = { allow: '허용', deny: '거부', step_up: '추가 확인', observe: '관찰',
  propose_revocation: '회수 제안', revoked: '회수됨', restored: '복구됨', failed: '실패' };

export function clearResults(root) {
  for (const el of root.querySelectorAll('[data-number]')) el.textContent = '—';
  for (const el of root.querySelectorAll('[data-domain]')) el.textContent = '결과 원본 미확인';
  root.querySelector('[data-rows]').replaceChildren();
  root.querySelector('[data-meta]').textContent = '';
  root.querySelector('[data-evidence]').textContent = '';
  root.querySelector('[data-comparison]').textContent = '';
}

function renderRules(root, rules) {
  if (!Array.isArray(rules?.ids) || rules.count !== rules.ids.length
      || rules.ids.some(id => typeof id !== 'string' || !/^[a-z][a-z0-9_.-]{0,79}$/u.test(id))) {
    throw new Error('invalid_rules');
  }
  root.querySelector('[data-rules]').textContent = `구현된 규칙 ${rules.count}개: ${rules.ids.join(', ')}. 운영 성공 횟수가 아닙니다.`;
}

export function renderSnapshot(root, input) {
  clearResults(root);
  const data = validateSnapshot(input);
  renderRules(root, data.rules);
  const rows = data.records.map(record => {
    const tr = root.ownerDocument.createElement('tr');
    for (const text of [record.number, labels[record.category], record.status === 'not_run' ? '미실행' : outcomes[record.outcome],
      record.at ?? '확인 시각 없음', record.policyRevision ?? '확인된 버전 없음']) {
      const td = root.ownerDocument.createElement('td');
      td.textContent = String(text);
      tr.append(td);
    }
    return tr;
  });
  for (const category of CATEGORIES) {
    const domain = data.domains[category];
    root.querySelector(`[data-domain="${category}"]`).textContent = domain.status !== 'no_records'
      ? `확인된 결과 ${domain.recorded}건 · 미실행 ${domain.notRun}건`
        + (domain.latestOutcome ? ` · 최근 결과 ${outcomes[domain.latestOutcome]}` : '')
        + (category === 'recovery' ? ` · 확인된 복구 정책 버전 ${domain.policyRevision ?? '미확인'}` : '')
      : '해당 분야 기록 없음';
  }
  root.querySelector('[data-rows]').replaceChildren(...rows);
  root.querySelector('[data-meta]').textContent = `운영 기록 시각 ${data.checkedAt} · 배포 커밋 ${data.commit ?? '미제공'}`;
  for (const el of root.querySelectorAll('[data-number]')) el.textContent = String(data.summary[el.dataset.number]);
  root.querySelector('[data-evidence]').textContent = JSON.stringify(maskedEvidence(data), null, 2);
  root.querySelector('[data-comparison]').textContent = '같은 응답의 합계·분야별 요약·상세 행 대조 일치 (운영 방어 성공 판정과 별개)';
}

export function mountOperations(root) {
  const button = root.querySelector('[data-refresh]');
  const state = root.querySelector('[data-state]');
  let version = 0;
  async function load() {
    const current = ++version;
    clearResults(root);
    root.querySelector('[data-api]').textContent = '작전실 API 조회 중';
    button.disabled = true;
    state.textContent = '운영 결과 원본을 확인하는 중입니다.';
    try {
      const response = await fetch('/api/ops', { cache: 'no-store', signal: AbortSignal.timeout(8000) });
      if (current !== version) return;
      root.querySelector('[data-api]').textContent = `이번 작전실 API 응답: HTTP ${response.status}`;
      const data = await response.json();
      if (current !== version) return;
      if (!response.ok) {
        if (response.status === 503 && data?.schema === 'aleph.ops.v1' && data.status === 'unavailable') {
          validateUnavailable(data);
          renderRules(root, data.rules);
          for (const category of CATEGORIES) {
            const suffix = category === 'recovery' ? ' · 복구 버전 미확인' : '';
            root.querySelector(`[data-domain="${category}"]`).textContent = '원본 조회 불가 · 실행 여부 미확인' + suffix;
          }
          root.querySelector('[data-meta]').textContent = `작전실 조회 시각 ${data.queriedAt} · 운영 결과 시각 미제공`;
          root.querySelector('[data-evidence]').textContent = JSON.stringify(maskedEvidence(data), null, 2);
          root.querySelector('[data-comparison]').textContent = '서버에 운영 결과·집계 없음: 화면 수치 미표시';
          state.textContent = data.error === 'operations_source_not_connected'
            ? '운영 결과 원본 미연결입니다. 실제 결과를 조회하지 못했으며 수치를 표시하지 않습니다.'
            : '운영 결과 원본을 읽거나 검증하지 못했습니다. 수치를 표시하지 않습니다.';
          return;
        }
        throw new Error('api_failed');
      }
      renderSnapshot(root, data);
      state.textContent = '같은 서버 응답의 원본 기록과 합계를 대조했습니다. 심판 통과 판정이 아닙니다.';
    } catch {
      if (current !== version) return;
      clearResults(root);
      state.textContent = '운영 기록 조회 또는 대조에 실패했습니다. 이전 수치와 기록을 비웠습니다.';
    } finally {
      if (current === version) button.disabled = false;
    }
  }
  button.addEventListener('click', load);
  return load();
}

if (typeof document !== 'undefined') {
  for (const root of document.querySelectorAll('[data-operations]')) void mountOperations(root);
}
