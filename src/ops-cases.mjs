import { decide, RULE_IDS } from './decider.mjs';
import { detect } from './detect.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

export const FIXTURE_CASES = Object.freeze([
  ['registered_device_read', 6, '등록 기기 가상 요청 허용'],
  ['unregistered_device_read', 6, '미등록 기기 가상 요청 거부'],
  ['composite_risk_step_up', 7, '복합 이상 가상 요청 재확인'],
  ['engine_verified_step_up', 7, '재확인된 가상 요청 허용'],
  ['normal_read_detection', 9, '정상 조회 가상 사건 관찰'],
  ['burst_read_detection', 9, '조회 폭주 가상 사건 회수 제안'],
]);

// Only these fixed fixtures can run through the API. Request-supplied identities/events are never used.
export async function runOpsCase(id) {
  if (!FIXTURE_CASES.some(([name]) => name === id)) return null;
  if (id.endsWith('_detection')) {
    const count = id === 'normal_read_detection' ? 30 : 121;
    const start = Date.UTC(2026, 9, 1);
    const events = Array.from({ length: count }, (_, i) => ({
      at: new Date(start + i * 2000).toISOString(), method: 'GET',
      identity: { sub: 'learner_fixture' }, deviceId: 'b'.repeat(16),
    }));
    const result = detect(events);
    const expected = count === 30 ? 'observe' : 'propose_revocation';
    return { source: 'student_fixture', ready: result.action === expected,
      action: result.action === expected ? expected : 'unexpected', eventCount: count };
  }
  const { normal, suspicious } = fixtureRequests();
  const request = id === 'composite_risk_step_up' || id === 'engine_verified_step_up'
    ? suspicious : normal;
  if (id === 'unregistered_device_read') request.deviceRegistered = false;
  if (id === 'engine_verified_step_up') request.stepUp = { verified: true, authAgeSeconds: 60 };
  const result = await decide(request);
  const expected = id === 'unregistered_device_read' ? 'deny'
    : id === 'composite_risk_step_up' ? 'step_up' : 'allow';
  const valid = result?.schema === request.schema && result.requestId === request.requestId
    && Object.keys(result).sort().join(',') === 'decision,reasonCode,requestId,ruleIds,schema'
    && Array.isArray(result.ruleIds) && result.ruleIds.length > 0
    && result.ruleIds.every(rule => RULE_IDS.includes(rule));
  return { source: 'student_fixture', ready: valid && result.decision === expected,
    decision: ['allow', 'deny', 'step_up'].includes(result?.decision) ? result.decision : 'unexpected' };
}
