import { databaseRequest, requireStudentIdentity, UUID } from './notes.js';
import { matchesResourceIdHeader, RESOURCE_KINDS, resourceId } from '../src/resource-id.mjs';
import { restoreMemo } from '../src/restore.mjs';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json({ error: 'Server configuration missing.' });
  }

  try {
    const identity = await requireStudentIdentity(req);
    if (!identity) return res.status(401).json({ error: 'Authentication required.' });
    const id = req.body?.id;
    if (!UUID.test(id ?? '')
        || !matchesResourceIdHeader(req, resourceId(RESOURCE_KINDS.memo, id))) {
      return res.status(400).json({ error: 'A valid note resource ID is required.' });
    }
    const result = await restoreMemo({ identity, id: req.body?.id, databaseRequest,
      supabaseUrl, supabaseSecretKey });
    return res.status(result.status).json(result.body);
  } catch {
    return res.status(500).json({ error: 'Failed to restore note.' });
  }
}
