import { decide as decideZtna } from '../../src/decider.mjs';
import { decide as inspectKnownCve } from './decide.mjs';
import { getActiveDenials } from './respond.mjs';

// Supply the engine request and its server-collected alert separately.
// Inspection cannot authorize a request denied by existing ZTNA rules.
export async function checkAccess(request, alert, options = {}) {
  const ztna = await decideZtna(request);
  const inspection = inspectKnownCve(alert);
  const denyRules = await getActiveDenials(alert, options);
  return { ztna, inspection, denyRules, notify: inspection.action !== 'record',
    proceed: ztna.decision === 'allow' && inspection.action !== 'block' && denyRules.length === 0 };
}
