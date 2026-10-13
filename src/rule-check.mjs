import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const cases = new Set([
  'registered_device_read', 'unregistered_device_read',
  'composite_risk_step_up', 'engine_verified_step_up',
  'normal_read_detection', 'unusual_network_burst_revocation_proposal',
]);

export async function runRuleCheck(caseId) {
  if (typeof caseId !== 'string' || !cases.has(caseId)) return null;
  const { normal, suspicious } = fixtureRequests();
  if (caseId === 'registered_device_read' || caseId === 'unregistered_device_read') {
    const request = { ...normal, deviceRegistered: caseId === 'registered_device_read' };
    const result = await decide(request);
    return { ready: result.decision === (request.deviceRegistered ? 'allow' : 'deny'),
      source: 'student_fixture' };
  }
  if (caseId === 'composite_risk_step_up' || caseId === 'engine_verified_step_up') {
    const request = caseId === 'engine_verified_step_up'
      ? { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } } : suspicious;
    const result = await decide(request);
    return { ready: result.decision === (caseId === 'engine_verified_step_up' ? 'allow' : 'step_up'),
      source: 'student_fixture' };
  }
  const start = Date.UTC(2026, 9, 1);
  const count = caseId === 'normal_read_detection' ? 30 : 121;
  const events = Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * 2000).toISOString(), method: 'GET',
    identity: { sub: 'learner_fixture' }, deviceId: 'b'.repeat(16),
  }));
  const result = detect(events);
  return { ready: result.action === (count === 30 ? 'observe' : 'propose_revocation'),
    source: 'student_fixture' };
}
