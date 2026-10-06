import { databaseRequest, requireStudentIdentity, UUID } from '../notes.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!['GET', 'PUT', 'DELETE'].includes(req.method)) {
    res.setHeader('Allow', 'GET, PUT, DELETE');
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

    const id = Array.isArray(req.query?.id) ? req.query.id[0] : req.query?.id;
    if (typeof id !== 'string' || !UUID.test(id)) {
      return res.status(400).json({ error: 'A valid note id is required.' });
    }

    const endpoint = new URL('/rest/v1/notes', supabaseUrl);
    endpoint.searchParams.set('id', `eq.${id}`);
    if (req.method === 'GET') {
      endpoint.searchParams.set('select', 'id,title,content,owner_id');
      const response = await databaseRequest(endpoint, supabaseSecretKey);
      if (!response.ok) throw new Error('note_read_failed');
      const rows = await response.json();
      if (!Array.isArray(rows)) throw new Error('invalid_note_response');
      if (!rows.length || rows[0].owner_id !== identity.userId) {
        return res.status(404).json({ error: 'Note not found.' });
      }
      const { title, content } = rows[0];
      return res.status(200).json({ id, title, body: content });
    }

    if (req.method === 'PUT') {
      const { title, body } = req.body ?? {};
      if (typeof title !== 'string' || !title.trim()
          || typeof body !== 'string' || !body.trim()) {
        return res.status(400).json({ error: 'A valid title and body are required.' });
      }

      const existingEndpoint = new URL(endpoint);
      existingEndpoint.searchParams.set('select', 'id,owner_id');
      const existingResponse = await databaseRequest(existingEndpoint, supabaseSecretKey);
      if (!existingResponse.ok) throw new Error('note_owner_read_failed');
      const existingRows = await existingResponse.json();
      if (!Array.isArray(existingRows)) throw new Error('invalid_note_response');
      if (!existingRows.length || existingRows[0].owner_id !== identity.userId) {
        return res.status(404).json({ error: 'Note not found.' });
      }

      endpoint.searchParams.set('owner_id', `eq.${identity.userId}`);
      endpoint.searchParams.set('select', 'id,owner_id');
      const response = await databaseRequest(endpoint, supabaseSecretKey, {
        method: 'PATCH',
        headers: { Prefer: 'return=representation' },
        body: JSON.stringify({ title, content: body }),
      });
      if (!response.ok) throw new Error('note_update_failed');
      const rows = await response.json();
      if (!Array.isArray(rows)) throw new Error('invalid_note_response');
      if (!rows.length || rows[0].owner_id !== identity.userId) {
        return res.status(404).json({ error: 'Note not found.' });
      }
      return res.status(200).json({ id });
    }

    endpoint.searchParams.set('owner_id', `eq.${identity.userId}`);
    endpoint.searchParams.set('select', 'id,owner_id');
    const response = await databaseRequest(endpoint, supabaseSecretKey, {
      method: 'DELETE',
      headers: { Prefer: 'return=representation' },
    });
    if (!response.ok) throw new Error('note_delete_failed');
    const rows = await response.json();
    if (!Array.isArray(rows)) throw new Error('invalid_note_response');
    if (!rows.length || rows[0].owner_id !== identity.userId) {
      return res.status(404).json({ error: 'Note not found.' });
    }
    return res.status(204).end();
  } catch {
    return res.status(500).json({ error: 'Failed to process note request.' });
  }
}
