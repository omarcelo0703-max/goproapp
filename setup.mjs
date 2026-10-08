// Configuración inicial: crea (o restablece la contraseña de) el usuario administrador.
// Solo funciona mientras exista la variable de entorno SETUP_TOKEN en Netlify, es decir,
// solo quien controla tu cuenta de Netlify puede usarla.
import { createHash, timingSafeEqual } from 'node:crypto';
import { admin } from '@netlify/identity';
import {
  json, fail, checkOrigin, readJson, normalizeUsuario, emailFor, USER_RE, rolesOf, passwordProblem, failDelay,
} from '../lib/shared.mjs';

const sha = (s) => createHash('sha256').update(String(s)).digest();

export default async (req) => {
  const token = process.env.SETUP_TOKEN;
  if (!token) return fail(404, 'No disponible');
  if (req.method !== 'POST') return fail(405, 'Método no permitido');
  if (!checkOrigin(req)) return fail(403, 'Solicitud no permitida');

  try {
    const body = await readJson(req, 10_000);
    if (!timingSafeEqual(sha(body.codigo ?? ''), sha(token))) { await failDelay(); return fail(403, 'Código incorrecto'); }

    const usuario = normalizeUsuario(body.usuario);
    if (!USER_RE.test(usuario)) return fail(400, 'El usuario debe tener entre 3 y 30 caracteres: letras minúsculas, números, punto, guion o guion bajo');
    const problema = passwordProblem(body.password, usuario);
    if (problema) return fail(400, problema);

    const email = emailFor(usuario);
    let existente = null;
    for (let page = 1; page <= 10 && !existente; page++) {
      const batch = await admin.listUsers({ page, perPage: 100 });
      existente = batch.find((u) => String(u.email || '').toLowerCase() === email) || null;
      if (batch.length < 100) break;
    }

    if (existente) {
      await admin.updateUser(existente.id, { password: body.password, confirm: true, app_metadata: { roles: ['admin'] } });
      return json({ ok: true, accion: 'actualizado' });
    }

    const creado = await admin.createUser({
      email, password: body.password,
      data: { app_metadata: { roles: ['admin'] }, user_metadata: { full_name: usuario } },
    });
    if (!rolesOf(creado).includes('admin')) await admin.updateUser(creado.id, { app_metadata: { roles: ['admin'] } });
    return json({ ok: true, accion: 'creado' });
  } catch (err) {
    if (err && err.status && err.status < 500) return fail(err.status, err.message);
    console.error('Error en /api/setup:', err);
    return fail(500, 'No se pudo completar la configuración');
  }
};

export const config = { path: '/api/setup' };
