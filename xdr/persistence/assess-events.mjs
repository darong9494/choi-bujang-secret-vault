import { decide } from './decide.mjs';

const WINDOW_MS = 600000;
const CORRELATION_MS = 300000;
const normalizedPath = value => typeof value === 'string' ? value.replace(/\//gu, '\\').toLowerCase() : '';
const safeId = value => typeof value === 'string'
  && /^(?:[a-z]{1,16}-\d{1,12}|\d{1,16}(?:\.\d{1,16})?)$/u.test(value) ? value : null;

export function assessEvents(events, { agentName, baselinePaths, now = Date.now() } = {}) {
  if (!Array.isArray(events) || typeof agentName !== 'string' || !agentName
      || !Number.isSafeInteger(now) || !Number.isFinite(new Date(now).getTime())) {
    throw new Error('invalid_persistence_context');
  }
  if (baselinePaths != null && (!Array.isArray(baselinePaths)
      || !baselinePaths.every(path => typeof path === 'string' && path.length > 0))) {
    throw new Error('invalid_persistence_baseline');
  }
  const baseline = baselinePaths == null ? null : new Set(baselinePaths.map(normalizedPath));
  const recent = events.filter(event => event?.agent?.name === agentName
    && typeof event.timestamp === 'string' && Number.isFinite(Date.parse(event.timestamp))
    && Date.parse(event.timestamp) <= now && now - Date.parse(event.timestamp) < WINDOW_MS);
  const entries = recent.map(event => {
    const path = normalizedPath(event?.data?.path);
    const baselineStatus = !baseline || !path ? 'unknown' : baseline.has(path) ? 'listed' : 'unlisted';
    const decision = decide(event);
    const description = typeof event?.rule?.description === 'string' ? event.rule.description : '';
    if (decision.action === 'record' && baselineStatus === 'unlisted'
        && /추가|생성|등록|만들|바뀌|변경|생겼/u.test(description)
        && /서비스|예약 작업|시작|파일|무결성/u.test(description)) {
      Object.assign(decision, { action: 'alert', confidence: 0.55, reason: '검증된 평소 목록에 없는 변경 항목' });
    }
    return { event, description, path, id: safeId(event.id), at: Date.parse(event.timestamp),
      baselineStatus, decision };
  });
  const evidence = new Map();
  for (const entry of entries) {
    if (entry.id && entry.decision.action === 'block') evidence.set(entry.id, entry.at);
  }
  for (const file of entries) {
    if (!file.id || !file.path || !/(?:무결성|해시|파일 내용).*변경|실행 파일이 바뀌/u.test(file.description)) continue;
    for (const registration of entries) {
      if (!registration.id || file.id === registration.id || file.path !== registration.path
          || Math.abs(file.at - registration.at) > CORRELATION_MS
          || !/새 서비스|서비스 등록|예약 작업.*(?:등록|생성|만들)/u.test(registration.description)) continue;
      const unsigned = /서명 없는|서명이 없(?:습니다|음)|서명되지 않/u.test(file.description)
        || /서명 없는|서명이 없(?:습니다|음)|서명되지 않/u.test(registration.description);
      const temporary = /\\temp\\.+\.(?:exe|dll|sys|cmd|bat|ps1|vbs|lnk)$/iu.test(file.path);
      if (!unsigned || !temporary) continue;
      for (const entry of [file, registration]) {
        evidence.set(entry.id, entry.at);
        Object.assign(entry.decision, { action: 'block', confidence: 0.95,
          reason: '파일 무결성 변경과 지속 실행 등록의 결합' });
      }
    }
  }
  return { baselineStatus: baseline === null ? 'unavailable' : 'provided',
    findings: entries.map(entry => ({ alertId: entry.id, ...entry.decision, baselineStatus: entry.baselineStatus })),
    evidenceAlertIds: [...evidence.keys()].sort(),
    expiresAt: evidence.size ? new Date(Math.max(...evidence.values()) + WINDOW_MS).toISOString() : null };
}
