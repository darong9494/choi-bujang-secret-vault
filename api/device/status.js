import { requireStudentIdentity } from '../notes.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ approved: false, reason: 'method_not_allowed' });
  }
  try {
    const identity = await requireStudentIdentity(req);
    if (!identity) return res.status(401).json({ approved: false, reason: 'authentication_required' });
    // The student app has no trusted registration feed from the class engine.
    // Until the engine confirms this device, the safe state is unapproved.
    return res.status(200).json({ approved: false, reason: 'device_not_registered' });
  } catch {
    return res.status(503).json({ approved: false, reason: 'device_status_unavailable' });
  }
}
