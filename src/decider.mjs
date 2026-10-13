export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

function hasVerifiedIdentityAndDevice(request) {
  return request?.schema === 'aleph.decision.v1'
    && typeof request.classId === 'string' && request.classId.trim().length > 0
    && typeof request.projectId === 'string' && request.projectId.trim().length > 0
    && typeof request.subjectId === 'string' && request.subjectId.trim().length > 0
    && typeof request.deviceId === 'string' && /^[a-f0-9]{16}$/u.test(request.deviceId);
}

function isNotesRead(request) {
  if (request?.service !== 'notes' || request.method !== 'GET') return false;
  return [
    ['GET /notes', /^\/notes$/u],
    ['GET /notes/:id', /^\/notes\/[^/]+$/u],
    ['GET /api/notes', /^\/api\/notes$/u],
    ['GET /api/notes/:id', /^\/api\/notes\/[^/]+$/u],
  ].some(([route, pathPattern]) => request.route === route && pathPattern.test(request.path));
}

function hasCompositeRisk(request) {
  const signals = request?.signals;
  const hour = signals?.hour;
  const unusualHour = Number.isInteger(hour) && hour >= 0 && hour <= 23
    && (hour < 6 || hour >= 23);
  const unusualNetwork = signals?.network === 'unusual';
  const corroboratingEvent = Array.isArray(request?.recentEvents)
    && request.recentEvents.some(event => event?.kind === 'risk_signal'
      && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0 && event.ageSeconds <= 300
      && Number.isInteger(event.count) && event.count >= 10);
  // Region is deliberately excluded: a region value alone is not reliable access evidence.
  return unusualNetwork && unusualHour && corroboratingEvent;
}

function hasFreshEngineVerifiedStepUp(request) {
  const stepUp = request?.stepUp;
  return stepUp?.verified === true && Number.isInteger(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= 900;
}

export async function decide(request) {
  if (request?.deviceRegistered !== true || !hasVerifiedIdentityAndDevice(request)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  if (!isNotesRead(request)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'starter_not_ready',
      ruleIds: ['device_registered'],
    };
  }

  if (hasCompositeRisk(request) && !hasFreshEngineVerifiedStepUp(request)) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['device_registered', 'step_up_required'],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}
