import { checkAccess as checkExisting } from '../persistence/check-access.mjs';
import { assessEvents } from './assess-events.mjs';
import { getActiveDenials } from './respond.mjs';

// Account-to-subject bindings must be server verified, not browser-supplied claims.
export async function checkAccess(request, requestAlert, context = {}) {
  const existing = await checkExisting(request, requestAlert, context.persistence ?? {});
  const binding = context.binding;
  const bound = binding && typeof binding.agentName === 'string' && binding.agentName.length > 0
    && typeof binding.sourceAccount === 'string' && binding.sourceAccount.length > 0
    && typeof binding.subjectId === 'string' && binding.subjectId.length > 0
    && binding.subjectId === request?.subjectId && binding.classId === request?.classId
    && binding.projectId === request?.projectId;
  const privilege = bound ? assessEvents(context.events ?? [], {
    agentName: binding.agentName, account: binding.sourceAccount,
    knownAdminAccounts: context.knownAdminAccounts, now: context.now ?? Date.now(),
  }) : { baselineStatus: 'unavailable', findings: [], evidenceAlertIds: [], expiresAt: null };
  const privilegeDenyRules = await getActiveDenials(request, {
    rulesPath: context.rulesPath, clock: () => context.now ?? Date.now(),
  });
  const evidenceAlertIds = [...new Set([...privilege.evidenceAlertIds,
    ...privilegeDenyRules.flatMap(rule => rule.evidenceAlertIds)])].sort();
  const expiresAt = evidenceAlertIds.length ? new Date(Math.max(
    privilege.expiresAt ? Date.parse(privilege.expiresAt) : 0,
    ...privilegeDenyRules.map(rule => Date.parse(rule.expiresAt)),
  )).toISOString() : null;
  const revocation = evidenceAlertIds.length ? {
    action: 'revoke_sessions', subjectId: request.subjectId,
    evidenceAlertIds, expiresAt,
  } : null;
  return { ...existing, privilege, privilegeDenyRules, revocation,
    accountBindingStatus: bound ? 'matched' : 'unverified',
    notify: existing.notify || privilege.findings.some(finding => finding.action !== 'record'),
    proceed: existing.proceed && revocation === null };
}
