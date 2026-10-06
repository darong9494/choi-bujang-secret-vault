import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export async function requireStudentIdentity(req) {
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  const vercelUrl = process.env.VERCEL_URL;
  if (!supabaseSecretKey || !vercelUrl || !/^[a-z0-9.-]+\.vercel\.app$/iu.test(vercelUrl)) {
    throw new Error('server_configuration_missing');
  }
  const verifyLogin = createLoginVerifier({
    config: { ...config, publicAppUrl: `https://${vercelUrl}/` },
    supabaseSecretKey,
  });
  const identity = await verifyLogin(req.headers.authorization);
  return identity?.kind === 'student' ? identity : null;
}

function databaseRequest(url, secretKey, options = {}) {
  return fetch(url, {
    ...options,
    headers: {
      apikey: secretKey,
      Authorization: `Bearer ${secretKey}`,
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    },
  });
}

function parseNote(value, { allowId = false } = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || typeof value.title !== 'string' || !value.title.trim()
      || typeof value.body !== 'string' || !value.body.trim()) return null;
  if (allowId && value.id !== undefined && (typeof value.id !== 'string' || !UUID.test(value.id))) return null;
  return { ...(allowId && value.id ? { id: value.id } : {}), title: value.title, body: value.body };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!['GET', 'POST'].includes(req.method)) {
    res.setHeader('Allow', 'GET, POST');
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

    if (req.method === 'GET') {
      const endpoint = new URL('/rest/v1/notes?select=id,title,content&order=created_at.asc', supabaseUrl);
      endpoint.searchParams.set('owner_id', `eq.${identity.userId}`);
      const response = await databaseRequest(endpoint, supabaseSecretKey);
      if (!response.ok) throw new Error('notes_read_failed');
      const rows = await response.json();
      if (!Array.isArray(rows)) throw new Error('invalid_notes_response');
      return res.status(200).json(rows.map(({ id, title, content }) => ({ id, title, body: content })));
    }

    const note = parseNote(req.body, { allowId: true });
    if (!note) return res.status(400).json({ error: 'A valid title and body are required.' });
    const id = note.id ?? randomUUID();
    const endpoint = new URL('/rest/v1/notes', supabaseUrl);
    const response = await databaseRequest(endpoint, supabaseSecretKey, {
      method: 'POST',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify({ id, title: note.title, content: note.body, owner_id: identity.userId }),
    });
    if (!response.ok) throw new Error('note_create_failed');
    return res.status(201).json({ id });
  } catch {
    return res.status(500).json({ error: 'Failed to process notes request.' });
  }
}

export { databaseRequest, UUID };
