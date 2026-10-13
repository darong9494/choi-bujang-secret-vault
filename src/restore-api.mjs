import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const BACKUP_LIMIT = 1024 * 1024;

const send = (response, status, payload) => {
  response.setHeader('Cache-Control', 'no-store');
  return response.status(status).json(payload);
};

export function noteHash(note) {
  return createHash('sha256')
    .update(JSON.stringify([note.id, note.owner_id, note.title, note.content]))
    .digest('hex');
}

export function loadBackupFromEnv(env = process.env) {
  const raw = env.NOTES_BACKUP_JSON;
  if (typeof raw !== 'string' || !raw || raw.length > BACKUP_LIMIT) return null;
  try {
    const backup = JSON.parse(raw);
    return Array.isArray(backup) && backup.length <= 1000 ? backup : null;
  } catch {
    return null;
  }
}

export function createRestoreApi({ verify, db, loadBackup }) {
  return async function restore(request, response) {
    try {
      const identity = await verify(request.headers?.authorization);
      if (!identity || typeof identity.userId !== 'string' || !UUID.test(identity.userId)) {
        response.setHeader('WWW-Authenticate', 'Bearer');
        return send(response, 401, { error: 'UNAUTHENTICATED' });
      }
      if (request.method !== 'POST') {
        response.setHeader('Allow', 'POST');
        return send(response, 405, { error: 'METHOD_NOT_ALLOWED' });
      }

      const id = request.query?.noteId;
      if (typeof id !== 'string' || !UUID.test(id)) {
        return send(response, 400, { error: 'INVALID_REQUEST' });
      }

      const backup = await loadBackup();
      if (!Array.isArray(backup)) return send(response, 503, { error: 'BACKUP_UNAVAILABLE' });
      const matches = backup.filter(item => item && item.id === id);
      if (matches.length !== 1 || matches[0].owner_id !== identity.userId) {
        return send(response, 404, { error: 'NOT_FOUND' });
      }
      const entry = matches[0];
      if (!UUID.test(entry.id ?? '') || !UUID.test(entry.owner_id ?? '')
          || typeof entry.title !== 'string' || typeof entry.content !== 'string'
          || typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(entry.sha256)
          || noteHash(entry) !== entry.sha256) {
        return send(response, 409, { error: 'BACKUP_INVALID' });
      }

      const current = await db.get(id, identity.userId);
      if (current && current.id === id && current.owner_id === identity.userId
          && noteHash(current) === entry.sha256) {
        return send(response, 200, { id, restored: false, sha256: entry.sha256 });
      }
      if (current) {
        await db.update(id, identity.userId, { title: entry.title, content: entry.content });
      } else if (!(await db.insert({ id, owner_id: identity.userId,
        title: entry.title, content: entry.content }))) {
        return send(response, 409, { error: 'CONFLICT' });
      }

      const after = await db.get(id, identity.userId);
      if (!after || after.id !== id || after.owner_id !== identity.userId
          || noteHash(after) !== entry.sha256) {
        return send(response, 500, { error: 'RESTORE_MISMATCH' });
      }
      return send(response, 200, { id, restored: true, sha256: entry.sha256 });
    } catch {
      return send(response, 500, { error: 'SERVER_ERROR' });
    }
  };
}
