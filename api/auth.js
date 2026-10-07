const MAX_BODY_LENGTH = 8192;

function validCredentials(body) {
  return body && typeof body === 'object' && !Array.isArray(body)
    && typeof body.email === 'string' && body.email.length <= 320
    && typeof body.password === 'string' && body.password.length <= 1024;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseApiKey = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY;
  if (!supabaseUrl || !supabaseApiKey) {
    return res.status(500).json({ error: 'Server configuration missing.' });
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || JSON.stringify(body).length > MAX_BODY_LENGTH
      || !['login', 'refresh'].includes(body.action)) {
    return res.status(400).json({ error: 'Invalid authentication request.' });
  }
  if (body.action === 'login' && !validCredentials(body)) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }
  if (body.action === 'refresh'
      && (typeof body.refresh_token !== 'string' || body.refresh_token.length > 4096)) {
    return res.status(400).json({ error: 'A valid session is required.' });
  }

  try {
    const grant = body.action === 'login' ? 'password' : 'refresh_token';
    const response = await fetch(new URL(`/auth/v1/token?grant_type=${grant}`, supabaseUrl), {
      method: 'POST',
      headers: { apikey: supabaseApiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify(body.action === 'login'
        ? { email: body.email, password: body.password }
        : { refresh_token: body.refresh_token }),
    });
    const result = await response.json();
    if (!response.ok) {
      return res.status(response.status === 400 || response.status === 401 ? 401 : 502)
        .json({ error: '로그인 정보를 확인하거나 다시 로그인해 주세요.' });
    }
    return res.status(200).json({
      access_token: result.access_token,
      refresh_token: result.refresh_token,
      expires_at: result.expires_at,
      user: { email: result.user?.email ?? null },
    });
  } catch {
    return res.status(502).json({ error: '인증 서버에 연결하지 못했습니다.' });
  }
}
