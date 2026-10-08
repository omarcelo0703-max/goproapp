// Los datos del club (alumnos, pagos, asistencia...). Solo para usuarios con sesión.
import { getStore } from '@netlify/blobs';
import { currentUser, json, fail, checkOrigin, readJson, deepMerge, sanitizeState } from '../lib/shared.mjs';

const STORE = 'gopro-club';
const KEY = 'state';
const store = () => getStore({ name: STORE, consistency: 'strong' });

// Aplica un cambio parcial. Si otra persona guardó al mismo tiempo, se vuelve a intentar
// sobre la versión más nueva, así nadie pisa el trabajo del otro.
async function applyPatch(s, patch) {
  for (let intento = 0; intento < 6; intento++) {
    const cur = await s.getWithMetadata(KEY, { type: 'json' });
    const base = cur && cur.data ? cur.data : {};
    const next = deepMerge(structuredClone(base), patch);
    const res = cur
      ? await s.setJSON(KEY, next, { onlyIfMatch: cur.etag })
      : await s.setJSON(KEY, next, { onlyIfNew: true });
    if (res.modified) return res.etag;
  }
  const e = new Error('Conflicto de guardado'); e.status = 409; throw e;
}

export default async (req) => {
  const user = await currentUser();
  if (!user) return fail(401, 'No autenticado');
  const s = store();

  try {
    if (req.method === 'GET') {
      const v = new URL(req.url).searchParams.get('v');
      if (v) {
        const meta = await s.getMetadata(KEY);
        if (meta && meta.etag === v) return json({ unchanged: true, version: v });
      }
      const cur = await s.getWithMetadata(KEY, { type: 'json' });
      if (!cur || !cur.data) return json({ exists: false, state: null, version: null });
      return json({ exists: true, state: cur.data, version: cur.etag });
    }

    if (req.method === 'POST') {
      if (!checkOrigin(req)) return fail(403, 'Solicitud no permitida');
      const body = await readJson(req);

      if (body && body.replace !== undefined) {
        if (!user.isAdmin) return fail(403, 'Solo el administrador puede restaurar un respaldo');
        const next = sanitizeState(body.replace, { requireStudents: true });
        const cur = await s.getWithMetadata(KEY, { type: 'json' });
        if (cur && cur.data) await s.setJSON('state-before-restore', cur.data); // copia de seguridad del estado anterior
        const res = await s.setJSON(KEY, next);
        return json({ ok: true, version: res.etag });
      }

      if (body && body.patch !== undefined) {
        const patch = sanitizeState(body.patch);
        const version = await applyPatch(s, patch);
        return json({ ok: true, version });
      }
      return fail(400, 'Solicitud inválida');
    }

    return fail(405, 'Método no permitido');
  } catch (err) {
    if (err && err.status) return fail(err.status, err.message);
    console.error('Error en /api/data:', err);
    return fail(500, 'Error del servidor');
  }
};

export const config = { path: '/api/data' };
