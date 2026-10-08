// Inicio de sesión: usuario + contraseña. La verificación ocurre aquí, en el servidor.
import { login, logout } from '@netlify/identity';
import { json, fail, checkOrigin, normalizeUsuario, emailFor, USER_RE, rolesOf, failDelay } from '../lib/shared.mjs';

export default async (req) => {
  if (req.method !== 'POST') return fail(405, 'Método no permitido');
  if (!checkOrigin(req)) return fail(403, 'Solicitud no permitida');

  let body;
  try { body = await req.json(); } catch { return fail(400, 'Solicitud inválida'); }

  const usuario = normalizeUsuario(body && body.usuario);
  const password = typeof (body && body.password) === 'string' ? body.password : '';
  // Mensaje único para cualquier fallo: no revela si el usuario existe o no.
  const rechazar = async () => { await failDelay(); return fail(401, 'Usuario o contraseña incorrectos'); };

  if (!USER_RE.test(usuario) || !password || password.length > 200) return rechazar();

  let user;
  try { user = await login(emailFor(usuario), password); } catch { return rechazar(); }

  const roles = rolesOf(user);
  if (!roles.includes('admin') && !roles.includes('usuario')) {
    try { await logout(); } catch { /* ignorar */ }
    return rechazar();
  }
  return json({ ok: true });
};

export const config = { path: '/api/login' };
