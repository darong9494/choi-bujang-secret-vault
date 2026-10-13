import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[a-f0-9]{64}$/u;

export async function restoreMemo({ identity, id, databaseRequest: request,
  supabaseUrl, supabaseSecretKey }) {
  if (!identity || identity.kind !== 'student' || !UUID.test(identity.userId ?? '')) {
    return { status: 401, body: { error: 'Authentication required.' } };
  }
  if (!UUID.test(id ?? '')) {
    return { status: 400, body: { error: 'A valid note id is required.' } };
  }

  const backupEndpoint = new URL('/rest/v1/note_backups', supabaseUrl);
  backupEndpoint.searchParams.set('select', 'note_id,owner_id,title,content,content_sha256');
  backupEndpoint.searchParams.set('note_id', `eq.${id}`);
  backupEndpoint.searchParams.set('owner_id', `eq.${identity.userId}`);
  const backupResponse = await request(backupEndpoint, supabaseSecretKey);
  if (!backupResponse.ok) throw new Error('backup_read_failed');
  const backups = await backupResponse.json();
  if (!Array.isArray(backups)) throw new Error('invalid_backup_response');
  if (backups.length !== 1) return { status: 404, body: { error: 'Backup not found.' } };

  const backup = backups[0];
  if (backup.note_id !== id || backup.owner_id !== identity.userId) {
    return { status: 404, body: { error: 'Backup not found.' } };
  }
  if (typeof backup.title !== 'string' || typeof backup.content !== 'string') {
    return { status: 409, body: { error: 'Backup integrity check failed.' } };
  }
  const actualHash = createHash('sha256').update(backup.content, 'utf8').digest('hex');
  if (!SHA256.test(backup.content_sha256 ?? '')
      || actualHash !== backup.content_sha256) {
    return { status: 409, body: { error: 'Backup integrity check failed.' } };
  }

  const currentEndpoint = new URL('/rest/v1/notes', supabaseUrl);
  currentEndpoint.searchParams.set('select', 'id,owner_id');
  currentEndpoint.searchParams.set('id', `eq.${id}`);
  currentEndpoint.searchParams.set('owner_id', `eq.${identity.userId}`);
  const currentResponse = await request(currentEndpoint, supabaseSecretKey);
  if (!currentResponse.ok) throw new Error('note_owner_read_failed');
  const currentRows = await currentResponse.json();
  if (!Array.isArray(currentRows)) throw new Error('invalid_note_response');
  if (currentRows.length !== 1 || currentRows[0].owner_id !== identity.userId) {
    return { status: 404, body: { error: 'Note not found.' } };
  }

  const updateEndpoint = new URL('/rest/v1/notes', supabaseUrl);
  updateEndpoint.searchParams.set('id', `eq.${id}`);
  updateEndpoint.searchParams.set('owner_id', `eq.${identity.userId}`);
  updateEndpoint.searchParams.set('select', 'id,owner_id');
  const updateResponse = await request(updateEndpoint, supabaseSecretKey, {
    method: 'PATCH',
    headers: { Prefer: 'return=representation' },
    body: JSON.stringify({ title: backup.title, content: backup.content }),
  });
  if (!updateResponse.ok) throw new Error('note_restore_failed');
  const updatedRows = await updateResponse.json();
  if (!Array.isArray(updatedRows)) throw new Error('invalid_restore_response');
  if (updatedRows.length !== 1 || updatedRows[0].owner_id !== identity.userId) {
    return { status: 404, body: { error: 'Note not found.' } };
  }
  return { status: 200, body: { id, restored: true } };
}
