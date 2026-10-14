import { collectRequestChecks } from './request-checks.mjs';

export function createRequestChecksHandler({ config, verifyIdentity }) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return res.status(405).json({ error: 'method_not_allowed' });
    }
    const authorization = req.headers?.authorization;
    try {
      if (authorization && !(await verifyIdentity(req))) return res.status(401).json({ error: 'authentication_required' });
      return res.status(200).json(await collectRequestChecks(config, { authorization: authorization ?? null }));
    } catch {
      return res.status(503).json({ error: 'measurements_unavailable' });
    }
  };
}
