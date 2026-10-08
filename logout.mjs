import { logout } from '@netlify/identity';
import { json, fail, checkOrigin } from '../lib/shared.mjs';

export default async (req) => {
  if (req.method !== 'POST') return fail(405, 'Método no permitido');
  if (!checkOrigin(req)) return fail(403, 'Solicitud no permitida');
  try { await logout(); } catch { /* si no había sesión, no pasa nada */ }
  return json({ ok: true });
};

export const config = { path: '/api/logout' };
