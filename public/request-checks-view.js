const TYPES = { normal_public: '정상·공개 화면', normal_status: '정상·상태 조회', normal_protected: '정상·보호자료', forbidden: '금지' };
const RESULTS = { matched: '기대 응답 실측', mismatch: '응답 불일치', inconclusive: '확인 불가', not_run: '미실행', network_error: '응답 미확인' };
const REASONS = { expected_response_observed: '실제 응답 확인', unexpected_response: '기대와 다른 응답',
  route_or_resource_not_confirmed: '경로 미구현·대상 없음 가능성, 거부 증거로 쓰지 않음',
  response_unconfirmed: '요청했으나 응답을 확인하지 못함', login_required: '로그인 세션 필요',
  device_approval_not_confirmed: '서버 기기 승인 미확인', owned_note_not_available: '조회 가능한 본인 메모 미확인',
  engine_feed_not_connected: '운영 엔진 기록 미연결', second_account_receipt_required: '다른 실계정의 실제 접근 기록 필요' };

export function validateMeasurements(data) {
  if (data?.schema !== 'aleph.api-measurements.v1' || data.source !== 'student_api_measurements'
      || !Number.isFinite(Date.parse(data.checkedAt)) || !Array.isArray(data.rows)
      || data.finalAssault?.status !== 'not_run' || data.finalAssault.expectedCases !== 41
      || data.finalAssault.measuredCases !== null) throw new Error('invalid_measurements');
  const counts = { total: data.rows.length, matched: 0, mismatch: 0, inconclusive: 0, notRun: 0, networkError: 0 };
  const ids = new Set();
  for (const row of data.rows) {
    if (ids.has(row.id) || !Object.hasOwn(TYPES, row.kind) || !Object.hasOwn(RESULTS, row.result)
        || !Object.hasOwn(REASONS, row.reason) || !Number.isInteger(row.stage) || row.stage < 1 || row.stage > 11) throw new Error('invalid_row');
    ids.add(row.id);
    const unconfirmed = ['not_run', 'network_error'].includes(row.result);
    if (unconfirmed && (row.httpStatus !== null || row.requestId !== null || row.checkedAt !== null)) throw new Error('unrun_has_receipt');
    if (row.result === 'not_run' && row.attemptedAt !== null) throw new Error('unrun_was_sent');
    if (!unconfirmed && (!/^HTTP \d{3}; bodyBytes=\d+$/u.test(row.observed)
        || Number(row.observed.slice(5, 8)) !== row.httpStatus || !Number.isFinite(Date.parse(row.checkedAt)))) throw new Error('missing_receipt');
    const key = row.result === 'not_run' ? 'notRun' : row.result === 'network_error' ? 'networkError' : row.result;
    counts[key]++;
  }
  if (Object.keys(counts).some(k => data.summary?.[k] !== counts[k])) throw new Error('measurement_summary_mismatch');
  const normal = data.rows.some(r => r.kind === 'normal_protected' && r.result === 'matched' && r.httpStatus === 200);
  const denied = data.rows.filter(r => r.kind === 'forbidden' && r.result === 'matched' && [401, 403].includes(r.httpStatus)).length;
  if (data.confirmation?.normalProtectedAllowed !== normal || data.confirmation.forbiddenRejected !== denied
      || data.confirmation.requiredPairMeasured !== (normal && denied > 0)
      || data.confirmation.complete !== (normal && denied > 0 && data.rows.every(r => r.result === 'matched'))) throw new Error('measurement_confirmation_mismatch');
  return data;
}

export function clearMeasurements(root) {
  root.querySelector('[data-measurement-rows]').replaceChildren();
  root.querySelector('[data-measurement-summary]').textContent = '실측 기록 없음';
  root.querySelector('[data-measurement-confirmation]').textContent = '정상 보호자료 허용 + 금지 요청 거부: 확인 전';
}

export function renderMeasurements(root, input) {
  clearMeasurements(root);
  const data = validateMeasurements(input);
  const rows = data.rows.map(row => {
    const tr = root.ownerDocument.createElement('tr');
    for (const text of [row.stage, TYPES[row.kind], row.request, row.expected, row.observed,
      row.requestId ?? '미제공', row.checkedAt ?? '응답 확인 시각 없음',
      `${RESULTS[row.result]} · ${REASONS[row.reason]}`]) {
      const td = root.ownerDocument.createElement('td');
      td.textContent = String(text);
      tr.append(td);
    }
    return tr;
  });
  root.querySelector('[data-measurement-rows]').replaceChildren(...rows);
  const s = data.summary;
  root.querySelector('[data-measurement-summary]').textContent = `확인 시각 ${data.checkedAt} · ${s.total}개 계획 항목 · 기대 응답 ${s.matched} · 불일치 ${s.mismatch} · 확인 불가 ${s.inconclusive} · 미실행 ${s.notRun} · 응답 미확인 ${s.networkError}`;
  root.querySelector('[data-measurement-confirmation]').textContent = `정상 보호자료 허용 + 금지 요청 거부 실측: ${data.confirmation.requiredPairMeasured ? '두 결과 모두 확인' : '조건 미충족'}. 1~11단계 전체 확인: ${data.confirmation.complete ? '계획 항목 모두 실측' : '미완료'}. 41종 총공세: 미실행.`;
}

export function mountMeasurements(root, getAuthorization = () => null) {
  const button = root.querySelector('[data-run-measurements]');
  const save = root.querySelector('[data-save-measurements]');
  const state = root.querySelector('[data-measurement-state]');
  let version = 0;
  let pending;
  let lastRecord = null;
  save.disabled = true;
  save.addEventListener('click', () => {
    if (!lastRecord) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(lastRecord, null, 2) + '\n'], { type: 'application/json' }));
    const link = root.ownerDocument.createElement('a');
    link.href = url;
    link.download = 'student-api-measurements.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  button.addEventListener('click', async () => {
    const current = ++version;
    pending?.abort();
    pending = new AbortController();
    button.disabled = true;
    save.disabled = true;
    lastRecord = null;
    clearMeasurements(root);
    state.textContent = '고정된 읽기 요청을 보내 실제 응답을 확인하는 중입니다.';
    try {
      const authorization = getAuthorization();
      const response = await fetch('/api/request-checks', { method: 'POST', cache: 'no-store',
        headers: authorization ? { Authorization: authorization } : {},
        signal: AbortSignal.any([pending.signal, AbortSignal.timeout(30000)]) });
      if (current !== version) return;
      if (!response.ok) throw new Error('measurement_request_failed');
      const data = await response.json();
      if (current !== version) return;
      renderMeasurements(root, data);
      // Only the same public columns shown in the table are kept for download.
      lastRecord = { schema: data.schema, source: data.source, checkedAt: data.checkedAt,
        summary: { total: data.summary.total, matched: data.summary.matched, mismatch: data.summary.mismatch,
          inconclusive: data.summary.inconclusive, notRun: data.summary.notRun, networkError: data.summary.networkError },
        confirmation: { normalProtectedAllowed: data.confirmation.normalProtectedAllowed,
          forbiddenRejected: data.confirmation.forbiddenRejected, requiredPairMeasured: data.confirmation.requiredPairMeasured,
          complete: data.confirmation.complete },
        finalAssault: { status: data.finalAssault.status, expectedCases: data.finalAssault.expectedCases,
          measuredCases: data.finalAssault.measuredCases },
        rows: data.rows.map(({ id, stage, kind, request, expected, result, observed, reason,
          httpStatus, requestId, attemptedAt, checkedAt }) => ({ id, stage, kind, request, expected, result,
          observed, reason, httpStatus, requestId, attemptedAt, checkedAt })) };
      save.disabled = false;
      state.textContent = '이번 서버 응답의 실측 기록입니다. 운영 판정·총공세 통과 기록이 아닙니다.';
    } catch {
      if (current !== version) return;
      clearMeasurements(root);
      state.textContent = '실측 기록을 확인하지 못했습니다. 이전 표와 수치를 비웠습니다.';
    } finally { if (current === version) button.disabled = false; }
  });
  return () => {
    ++version;
    pending?.abort();
    clearMeasurements(root);
    lastRecord = null;
    save.disabled = true;
    button.disabled = false;
    state.textContent = '현재 로그인 상태로 새 실측을 실행하세요. 이전 세션의 결과는 비웠습니다.';
  };
}

if (typeof document !== 'undefined') {
  for (const root of document.querySelectorAll('[data-anonymous-measurements]')) mountMeasurements(root);
}
