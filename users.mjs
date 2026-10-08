// Gestión de usuarios: solo el administrador.
import { admin } from '@netlify/identity';
import {
  currentUser, json, fail, checkOrigin, readJson, normalizeUsuario, emailFor, usuarioFromEmail,
  isClubEmail, rolesOf, passwordProblem, USER_RE,
} from '../lib/shared.mjs';

async function listAll() {
  const out = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await admin.listUsers({ page, perPage: 100 });
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

const describe = (u) => {
  const roles = rolesOf(u);
  return {
    id: u.id,
    usuario: usuarioFromEmail(u.email),
    nombre: u.name || u.userMetadata?.full_name || usuarioFromEmail(u.email),
    rol: roles.includes('admin') ? 'Administrador' : 'Usuario',
    isAdmin: roles.includes('admin'),
    creado: u.createdAt || null,
  };
};

export default async (req) => {
  const me = await currentUser();
  if (!me) return fail(401, 'No autenticado');
  if (!me.isAdmin) return fail(403, 'Solo el administrador puede gestionar usuarios');
  if (req.method !== 'GET' && !checkOrigin(req)) return fail(403, 'Solicitud no permitida');

  try {
    if (req.method === 'GET') {
      const users = (await listAll())
        .filter((u) => isClubEmail(u.email) && (rolesOf(u).includes('admin') || rolesOf(u).includes('usuario')))
        .map(describe)
        .sort((a, b) => a.usuario.localeCompare(b.usuario));
      return json({ users });
    }

    const body = await readJson(req, 20_000);

    if (req.method === 'POST') { // crear usuario
      const usuario = normalizeUsuario(body.usuario);
      const nombre = String(body.nombre || '').trim().slice(0, 80);
      if (!USER_RE.test(usuario)) return fail(400, 'El usuario debe tener entre 3 y 30 caracteres: letras minúsculas, números, punto, guion o guion bajo');
      const problema = passwordProblem(body.password, usuario);
      if (problema) return fail(400, problema);

      let creado;
      try {
        creado = await admin.createUser({
          email: emailFor(usuario),
          password: body.password,
          data: { app_metadata: { roles: ['usuario'] }, user_metadata: { full_name: nombre || usuario } },
        });
      } catch (e) {
        if (e && (e.status === 409 || e.status === 422 || /already|registered|exist/i.test(String(e.message)))) {
          return fail(409, 'Ya existe un usuario con ese nombre');
        }
        console.error('No se pudo crear el usuario:', e);
        return fail(500, 'No se pudo crear el usuario');
      }
      // Por seguridad, confirmamos que quedó con su rol.
      if (!rolesOf(creado).includes('usuario')) {
        await admin.updateUser(creado.id, { app_metadata: { roles: ['usuario'] } });
      }
      return json({ ok: true, id: creado.id });
    }

    if (req.method === 'PATCH') { // cambiar la contraseña de un usuario
      const id = String(body.id || '');
      const objetivo = id ? await admin.getUser(id) : null;
      if (!objetivo || !isClubEmail(objetivo.email)) return fail(404, 'Usuario no encontrado');
      const problema = passwordProblem(body.password, usuarioFromEmail(objetivo.email));
      if (problema) return fail(400, problema);
      await admin.updateUser(id, { password: body.password });
      return json({ ok: true });
    }

    if (req.method === 'DELETE') { // eliminar usuario
      const id = String(body.id || '');
      if (id === me.id) return fail(400, 'No puedes eliminar tu propio usuario');
      const objetivo = id ? await admin.getUser(id) : null;
      if (!objetivo || !isClubEmail(objetivo.email)) return fail(404, 'Usuario no encontrado');
      if (rolesOf(objetivo).includes('admin')) return fail(400, 'No se puede eliminar al administrador');
      await admin.deleteUser(id);
      return json({ ok: true });
    }

    return fail(405, 'Método no permitido');
  } catch (err) {
    if (err && err.status && err.status < 500) return fail(err.status, err.message);
    console.error('Error en /api/users:', err);
    return fail(500, 'Error del servidor');
  }
};

export const config = { path: '/api/users' };
