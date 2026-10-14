import { decide } from './decide.mjs';

const WINDOW_MS = 600000;
const CHAIN_MS = 300000;
const normalize = value => typeof value === 'string' ? value.toLowerCase() : '';
const safeId = value => typeof value === 'string'
  && /^(?:[a-z]{1,16}-\d{1,12}|\d{1,16}(?:\.\d{1,16})?)$/u.test(value) ? value : null;

export function assessEvents(events, { agentName, account, knownAdminAccounts, now = Date.now() } = {}) {
  if (!Array.isArray(events) || typeof agentName !== 'string' || !agentName
      || typeof account !== 'string' || !account || !Number.isSafeInteger(now)
      || !Number.isFinite(new Date(now).getTime())) throw new Error('invalid_privilege_context');
  if (knownAdminAccounts != null && (!Array.isArray(knownAdminAccounts)
      || !knownAdminAccounts.every(value => typeof value === 'string' && value.length > 0))) {
    throw new Error('invalid_privilege_baseline');
  }
  const baseline = knownAdminAccounts == null ? null : new Set(knownAdminAccounts.map(normalize));
  const baselineRole = baseline === null ? 'unknown' : baseline.has(normalize(account)) ? 'known_admin' : 'not_listed';
  const recent = events.filter(event => event?.agent?.name === agentName
    && typeof event?.data?.srcuser === 'string' && normalize(event.data.srcuser) === normalize(account)
    && typeof event.timestamp === 'string' && Number.isFinite(Date.parse(event.timestamp))
    && Date.parse(event.timestamp) <= now && now - Date.parse(event.timestamp) < WINDOW_MS);
  const entries = recent.map(event => ({ event, id: safeId(event.id), at: Date.parse(event.timestamp),
    description: typeof event?.rule?.description === 'string' ? event.rule.description : '', decision: decide(event) }));
  const evidence = new Map();
  for (const entry of entries) {
    if (entry.id && entry.decision.action === 'block') evidence.set(entry.id, entry.at);
  }
  for (const addition of entries) {
    if (!addition.id || normalize(addition.event?.data?.group) !== 'administrators'
        || !/관리자 그룹.*(?:추가|들어가|들어왔)|관리자 그룹 추가/u.test(addition.description)
        || /실패|취소|아닙니다/u.test(addition.description)) continue;
    for (const execution of entries) {
      if (!execution.id || execution.id === addition.id || execution.at < addition.at
          || execution.at - addition.at > CHAIN_MS
          || !/관리자 명령.*실행|권한 명령.*실행|명령 실행/u.test(execution.description)
          || /실패|취소|명령은 없/u.test(execution.description)) continue;
      for (const entry of [addition, execution]) {
        evidence.set(entry.id, entry.at);
        Object.assign(entry.decision, { action: 'block', confidence: 0.95,
          reason: '동일 계정의 관리자 그룹 추가 후 명령 실행' });
      }
    }
  }
  return { baselineStatus: baseline === null ? 'unavailable' : 'provided',
    findings: entries.map(entry => ({ alertId: entry.id, ...entry.decision, baselineRole })),
    evidenceAlertIds: [...evidence.keys()].sort(),
    expiresAt: evidence.size ? new Date(Math.max(...evidence.values()) + WINDOW_MS).toISOString() : null };
}
