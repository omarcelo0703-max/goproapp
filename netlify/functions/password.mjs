// Cambiar la propia contraseña (pide la actual).
import { login, admin } from '@netlify/identity';
import { currentUser, json, fail, checkOrigin, readJson, passwordProblem, failDelay } from '../lib/shared.mjs';

export default async (req) => {
  if (req.method !== 'POST') return fail(405, 'Método no permitido');
  if (!checkOrigin(req)) return fail(403, 'Solicitud no permitida');
  const me = await currentUser();
  if (!me) return fail(401, 'No autenticado');

  try {
    const body = await readJson(req, 10_000);
    const problema = passwordProblem(body.nueva, me.usuario);
    if (problema) return fail(400, problema);
    try { await login(me.email, String(body.actual || '')); }
    catch { await failDelay(); return fail(403, 'La contraseña actual no es correcta'); }
    await admin.updateUser(me.id, { password: body.nueva });
    return json({ ok: true });
  } catch (err) {
    if (err && err.status && err.status < 500) return fail(err.status, err.message);
    console.error('Error en /api/password:', err);
    return fail(500, 'Error del servidor');
  }
};

export const config = { path: '/api/password' };
