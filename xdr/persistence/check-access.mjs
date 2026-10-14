import { checkAccess as checkExisting } from '../known-cve/check-access.mjs';
import { assessEvents } from './assess-events.mjs';
import { getActiveDenials } from './respond.mjs';

// `context` must come from server-owned mappings and events, never browser claims.
export async function checkAccess(request, requestAlert, context = {}) {
  const existing = await checkExisting(request, requestAlert);
  const binding = context.binding;
  const bound = binding && typeof binding.agentName === 'string' && binding.agentName.length > 0
    && /^[a-f0-9]{16}$/u.test(binding.deviceId) && binding.deviceId === request?.deviceId
    && binding.classId === request?.classId && binding.projectId === request?.projectId;
  const assessment = bound ? assessEvents(context.events ?? [], {
    agentName: binding.agentName, baselinePaths: context.baselinePaths,
    now: context.now ?? Date.now(),
  }) : { baselineStatus: 'unavailable', findings: [], evidenceAlertIds: [], expiresAt: null };
  const persistenceDenyRules = await getActiveDenials(request, {
    rulesPath: context.rulesPath, clock: () => context.now ?? Date.now(),
  });
  const evidenceAlertIds = [...new Set([...assessment.evidenceAlertIds,
    ...persistenceDenyRules.flatMap(rule => rule.evidenceAlertIds)])].sort();
  const expiry = [assessment.expiresAt, ...persistenceDenyRules.map(rule => rule.expiresAt)]
    .filter(Boolean).map(value => Date.parse(value));
  const quarantine = evidenceAlertIds.length ? {
    action: 'quarantine', deviceId: request.deviceId,
    evidenceAlertIds, expiresAt: new Date(Math.max(...expiry)).toISOString(),
  } : null;
  return { ...existing, assessment, quarantine, persistenceDenyRules, bindingStatus: bound ? 'matched' : 'unverified',
    notify: existing.notify || persistenceDenyRules.length > 0
      || assessment.findings.some(finding => finding.action !== 'record'),
    proceed: existing.proceed && quarantine === null };
}
