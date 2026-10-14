import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { checkAccess as checkExisting } from '../privilege/check-access.mjs';
import { decide } from './decide.mjs';
import { getActiveDenials } from './respond.mjs';

const safeId = value => typeof value === 'string'
  && /^(?:[a-z]{1,16}-\d{1,12}|\d{1,16}(?:\.\d{1,16})?)$/u.test(value) ? value : null;

// Context must come from the trusted server/engine, never from browser input.
export async function checkAccess(request, requestAlert, context = {}) {
  const existing = await checkExisting(request, requestAlert, context.privilege ?? {});
  const now = context.now ?? Date.now();
  const binding = context.binding;
  const bound = binding && typeof binding.agentName === 'string' && binding.agentName.trim()
    && typeof binding.deviceId === 'string' && /^[a-f0-9]{16}$/u.test(binding.deviceId)
    && binding.deviceId === request?.deviceId && binding.classId === request?.classId
    && binding.projectId === request?.projectId
    && typeof binding.classId === 'string' && binding.classId.trim()
    && typeof binding.projectId === 'string' && binding.projectId.trim();
  const baseline = context.baseline;
  const destinations = Array.isArray(baseline?.destinations)
    && baseline.destinations.every(ip => typeof ip === 'string' && isIP(ip) === 4)
    ? baseline.destinations : null;
  const baselineBytes = Number.isSafeInteger(baseline?.maxBytes) && baseline.maxBytes >= 0
    ? baseline.maxBytes : null;
  const findings = [];
  const denials = new Map();
  if (bound && Number.isSafeInteger(now) && Array.isArray(context.events)) {
    for (const event of context.events) {
      const at = typeof event?.timestamp === 'string' ? Date.parse(event.timestamp) : NaN;
      if (event?.agent?.name !== binding.agentName || !Number.isFinite(at)
        || at > now || now - at >= 600000) continue;
      const destination = event?.data?.dstip;
      const valid = typeof destination === 'string' && isIP(destination) === 4;
      let decision = decide(event);
      const amount = typeof event?.data?.bytes === 'number' ? event.data.bytes
        : typeof event?.data?.bytes === 'string' && /^\d+$/u.test(event.data.bytes) ? Number(event.data.bytes) : NaN;
      const unusual = valid && destinations !== null && !destinations.includes(destination);
      const larger = baselineBytes !== null && Number.isSafeInteger(amount) && amount > baselineBytes;
      if (decision.action === 'record' && (unusual || larger)) {
        decision = { action: 'alert', confidence: 0.55, reason: '검증된 평소 전송 기준선 이탈' };
      }
      const alertId = safeId(event.id);
      findings.push({ alertId, ...decision,
        destinationStatus: destinations === null ? 'unknown' : valid ? unusual ? 'unlisted' : 'listed' : 'unknown',
        volumeStatus: baselineBytes === null || !Number.isSafeInteger(amount) ? 'unknown' : larger ? 'above' : 'within' });
      if (decision.action !== 'block' || !valid || !alertId) continue;
      const entry = denials.get(destination) ?? { evidenceAlertIds: [], expires: 0 };
      entry.evidenceAlertIds = [...new Set([...entry.evidenceAlertIds, alertId])];
      entry.expires = Math.max(entry.expires, at + 600000);
      denials.set(destination, entry);
    }
  }
  const exfiltrationDenyRules = await getActiveDenials(request, {
    destination: context.destination, rulesPath: context.rulesPath, clock: () => now,
  });
  let match = typeof context.destination === 'string' ? denials.get(context.destination) : null;
  for (const rule of exfiltrationDenyRules) {
    match ??= { evidenceAlertIds: [], expires: 0 };
    match.evidenceAlertIds = [...new Set([...match.evidenceAlertIds, ...rule.evidenceAlertIds])];
    match.expires = Math.max(match.expires, Date.parse(rule.expiresAt));
  }
  const destinationDenial = match ? { action: 'deny_destination',
    destinationHash: createHash('sha256').update(context.destination).digest('hex'),
    evidenceAlertIds: match.evidenceAlertIds.sort(), expiresAt: new Date(match.expires).toISOString() } : null;
  return { ...existing, exfiltrationDenyRules, exfiltration: { findings,
    baselineStatus: destinations !== null || baselineBytes !== null ? 'provided' : 'unavailable' },
    destinationBindingStatus: bound ? 'matched' : 'unverified', destinationDenial,
    notify: existing.notify || findings.some(row => row.action !== 'record'),
    proceed: existing.proceed && destinationDenial === null };
}
