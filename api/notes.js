export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json({ error: 'Server configuration missing.' });
  }

  try {
    const endpoint = new URL('/rest/v1/notes?select=title,content&order=created_at.asc&limit=4', supabaseUrl);
    const response = await fetch(endpoint, {
      headers: {
        'apikey': supabaseSecretKey,
        'Authorization': `Bearer ${supabaseSecretKey}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch notes: ${response.statusText}`);
    }

    const data = await response.json();

    if (!Array.isArray(data)) throw new Error('invalid_notes_response');
    const notes = data.map(({ title, content }) => ({ title, content }));
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json(notes);
  } catch {
    return res.status(500).json({ error: 'Failed to retrieve notes' });
  }
}
