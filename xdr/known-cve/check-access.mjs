import { decide as decideZtna } from '../../src/decider.mjs';
import { decide as inspectKnownCve } from './decide.mjs';
import { getActiveDenials } from './respond.mjs';

// The caller supplies a server-collected alert separately from the 18-field contract.
// Only `proceed` authorizes continuing; an inspection never grants ZTNA access.
export async function checkAccess(request, alert, options = {}) {
  const ztna = await decideZtna(request);
  const inspection = inspectKnownCve(alert);
  const denyRules = await getActiveDenials(alert, options);
  return { ztna, inspection, denyRules,
    proceed: ztna.decision === 'allow' && inspection.action !== 'block' && denyRules.length === 0 };
}
