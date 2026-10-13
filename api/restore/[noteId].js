import { databaseRequest, requireStudentIdentity } from '../notes.js';
import { createRestoreApi, loadBackupFromEnv } from '../../src/restore-api.mjs';

function notesUrl(supabaseUrl, id, ownerId, select) {
  const endpoint = new URL('/rest/v1/notes', supabaseUrl);
  endpoint.searchParams.set('select', select);
  endpoint.searchParams.set('id', `eq.${id}`);
  endpoint.searchParams.set('owner_id', `eq.${ownerId}`);
  return endpoint;
}

async function rows(response) {
  if (!response.ok) throw new Error('notes_operation_failed');
  const result = await response.json();
  if (!Array.isArray(result)) throw new Error('invalid_notes_response');
  return result;
}

export default async function handler(req, res) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !supabaseSecretKey) {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(500).json({ error: 'Server configuration missing.' });
  }

  const db = {
    async get(id, ownerId) {
      const endpoint = notesUrl(supabaseUrl, id, ownerId, 'id,title,content,owner_id');
      const result = await rows(await databaseRequest(endpoint, supabaseSecretKey));
      if (result.length > 1) throw new Error('duplicate_note_id');
      return result[0] ?? null;
    },
    async insert(note) {
      const endpoint = new URL('/rest/v1/notes', supabaseUrl);
      const response = await databaseRequest(endpoint, supabaseSecretKey, {
        method: 'POST', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({
          id: note.id, owner_id: note.owner_id, title: note.title, content: note.content,
        }),
      });
      return response.ok;
    },
    async update(id, ownerId, patch) {
      const endpoint = notesUrl(supabaseUrl, id, ownerId, 'id,owner_id');
      return rows(await databaseRequest(endpoint, supabaseSecretKey, {
        method: 'PATCH', headers: { Prefer: 'return=representation' },
        body: JSON.stringify({ title: patch.title, content: patch.content }),
      }));
    },
  };
  const restore = createRestoreApi({
    verify: async authorization => requireStudentIdentity({ headers: { authorization } }),
    db,
    loadBackup: async () => loadBackupFromEnv(),
  });
  return restore(req, res);
}
