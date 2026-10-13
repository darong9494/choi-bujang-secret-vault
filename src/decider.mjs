export const RULE_IDS = Object.freeze(['device_registered']);

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

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}
