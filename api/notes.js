export default async function handler(req, res) {
  // Prevent non-GET requests
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json({ error: 'Database configuration missing on server.' });
  }

  try {
    // Fetch notes using PostgREST API with secret key (bypassing RLS safely on server-side)
    const response = await fetch(`${supabaseUrl}/rest/v1/notes?select=id,title,content,created_at`, {
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

    // Cache control & return sanitized response without leaking keys
    res.setHeader('Cache-Control', 's-maxage=1, stale-while-revalidate');
    return res.status(200).json(data);
  } catch (err) {
    // Log generic error on server side without revealing secret keys
    console.error('Error fetching notes from Supabase DB');
    return res.status(500).json({ error: 'Failed to retrieve notes' });
  }
}