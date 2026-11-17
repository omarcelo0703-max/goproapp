// Utilidades compartidas por todas las funciones del servidor.
import { getUser, refreshSession, verifyRequestOrigin } from '@netlify/identity';

// Los usuarios entran con "usuario" + contraseña. Por dentro, Identity pide un correo,
// así que cada usuario se guarda como  <usuario>@usuarios.gopro-club.app  (no recibe correos).
export const EMAIL_DOMAIN = 'usuarios.gopro-club.app';
export const USER_RE = /^[a-z0-9._-]{3,30}$/;

export const ALLOWED_KEYS = ['students', 'encargados', 'attendance', 'encargadoAttendance', 'pagos', 'cursos', 'nextId', 'nextEncargadoId'];
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Pequeña pausa tras un intento fallido de acceso (frena los intentos automáticos)
export const failDelay = () => sleep(Number(process.env.GOPRO_FAIL_DELAY_MS ?? 700));

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}
export const fail = (status, message) => json({ error: message }, status);

export const normalizeUsuario = (v) => String(v ?? '').trim().toLowerCase();
export const emailFor = (usuario) => `${usuario}@${EMAIL_DOMAIN}`;
export const isClubEmail = (e) => String(e || '').toLowerCase().endsWith('@' + EMAIL_DOMAIN);
export function usuarioFromEmail(e) {
  const s = String(e || '');
  return isClubEmail(s) ? s.slice(0, -(EMAIL_DOMAIN.length + 1)) : s;
}

export function rolesOf(u) {
  if (!u) return [];
  if (Array.isArray(u.roles)) return u.roles;
  const r = u.appMetadata?.roles ?? u.app_metadata?.roles;
  return Array.isArray(r) ? r : [];
}

// Protección CSRF: solo aceptamos peticiones que vengan de este mismo sitio.
export function checkOrigin(req) {
  try { verifyRequestOrigin(req); return true; } catch { return false; }
}

export function passwordProblem(pw, usuario) {
  if (typeof pw !== 'string' || pw.length < 8) return 'La contraseña debe tener al menos 8 caracteres';
  if (pw.length > 128) return 'La contraseña es demasiado larga';
  if (usuario && pw.toLowerCase() === String(usuario).toLowerCase()) return 'La contraseña no puede ser igual al usuario';
  return null;
}

// Devuelve el usuario conectado, o null si no hay sesión o si la cuenta no tiene permiso.
// Una cuenta sin rol (por ejemplo, alguien que se registró por su cuenta) NUNCA ve datos.
export async function currentUser() {
  try { await refreshSession(); } catch { /* si no hay sesión, seguimos */ }
  let u = null;
  try { u = await getUser(); } catch { u = null; }
  if (!u) return null;
  const roles = rolesOf(u);
  if (!roles.includes('admin') && !roles.includes('usuario')) return null;
  const usuario = usuarioFromEmail(u.email);
  return {
    id: u.id, email: u.email, usuario,
    nombre: u.name || u.userMetadata?.full_name || usuario,
    roles, isAdmin: roles.includes('admin'),
  };
}

export async function readJson(req, maxBytes = 4_000_000) {
  const text = await req.text();
  if (text.length > maxBytes) { const e = new Error('Demasiado grande'); e.status = 413; throw e; }
  try { return JSON.parse(text); } catch { const e = new Error('Solicitud inválida'); e.status = 400; throw e; }
}

/* ---------- Datos del club ---------- */
const isPlain = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function cloneSafe(v) {
  if (Array.isArray(v)) return v.map(cloneSafe);
  if (isPlain(v)) {
    const out = {};
    for (const k of Object.keys(v)) if (!FORBIDDEN_KEYS.has(k)) out[k] = cloneSafe(v[k]);
    return out;
  }
  return v;
}

// Misma regla que usa la app: los objetos se fusionan campo por campo; listas y valores simples se reemplazan.
export function deepMerge(target, source) {
  for (const k of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(k)) continue;
    const sv = source[k];
    if (isPlain(sv) && isPlain(target[k])) deepMerge(target[k], sv);
    else target[k] = cloneSafe(sv);
  }
  return target;
}

const bad = (msg) => { const e = new Error(msg); e.status = 400; return e; };

// Valida y limpia lo que llega del navegador: solo campos conocidos y con el tipo correcto.
export function sanitizeState(obj, { requireStudents = false } = {}) {
  if (!isPlain(obj)) throw bad('Datos inválidos');
  const out = {};
  for (const k of Object.keys(obj)) {
    if (!ALLOWED_KEYS.includes(k)) throw bad('Campo no permitido: ' + k);
    const v = obj[k];
    if (k === 'students' || k === 'encargados') {
      if (!Array.isArray(v) || v.length > 5000 || !v.every(isPlain)) throw bad('Lista inválida: ' + k);
    } else if (k === 'cursos') {
      if (!Array.isArray(v) || v.length > 40 || !v.every((c) => typeof c === 'string' && c.trim() && c.length <= 60)) throw bad('Cursos inválidos');
    } else if (k === 'nextId' || k === 'nextEncargadoId') {
      if (!Number.isInteger(v) || v < 1 || v > 1e9) throw bad('Contador inválido');
    } else if (!isPlain(v)) {
      throw bad('Datos inválidos: ' + k);
    }
    out[k] = cloneSafe(v);
  }
  if (requireStudents && !Array.isArray(out.students)) throw bad('Falta la lista de alumnos');
  return out;
}

/* ---------- Cambios parciales (patch) ---------- */
// Las listas de alumnos y encargados NO se envían enteras: se mandan operaciones sueltas
// (agregar / editar / quitar un elemento). Así, si dos personas guardan a la vez, el servidor
// aplica las dos sobre la versión más nueva y nadie pisa el trabajo del otro.
export const LIST_KEYS = ['students', 'encargados'];
const LIST_OPS = new Set(['add', 'update', 'remove']);
const MAX_OPS = 5000;

export function sanitizePatch(obj) {
  if (!isPlain(obj)) throw bad('Datos inválidos');
  const { listOps, ...rest } = obj;
  for (const k of LIST_KEYS) {
    if (k in rest) {
      // Una pestaña abierta con la versión anterior de la app intenta enviar la lista completa.
      throw bad('La app se actualizó. Recarga la página para seguir guardando.');
    }
  }
  const out = Object.keys(rest).length ? sanitizeState(rest) : {};
  if (listOps !== undefined) {
    if (!isPlain(listOps)) throw bad('Operaciones inválidas');
    const ops = {};
    for (const k of Object.keys(listOps)) {
      if (!LIST_KEYS.includes(k)) throw bad('Lista no permitida: ' + k);
      const arr = listOps[k];
      if (!Array.isArray(arr) || arr.length > MAX_OPS) throw bad('Operaciones inválidas: ' + k);
      ops[k] = arr.map((o) => {
        if (!isPlain(o) || !LIST_OPS.has(o.op)) throw bad('Operación inválida');
        if (o.op === 'remove') {
          if (!Number.isInteger(o.id)) throw bad('Operación inválida');
          return { op: 'remove', id: o.id };
        }
        if (!isPlain(o.item) || !Number.isInteger(o.item.id)) throw bad('Operación inválida');
        return { op: o.op, item: cloneSafe(o.item) };
      });
    }
    out.listOps = ops;
  }
  return out;
}

// Aplica las operaciones de lista sobre el estado (lo modifica en el lugar).
// - add: agrega el elemento; si ya existe uno con ese id, lo reemplaza.
// - update: reemplaza el elemento con ese id; si otra persona ya lo borró, se ignora
//   (así una edición vieja no "revive" a un alumno eliminado).
// - remove: lo quita de la lista.
export function applyListOps(state, listOps) {
  for (const k of Object.keys(listOps || {})) {
    const list = Array.isArray(state[k]) ? state[k] : [];
    for (const o of listOps[k]) {
      const id = o.op === 'remove' ? o.id : o.item.id;
      const idx = list.findIndex((x) => x && x.id === id);
      if (o.op === 'remove') { if (idx >= 0) list.splice(idx, 1); }
      else if (idx >= 0) list[idx] = o.item;
      else if (o.op === 'add') list.push(o.item);
    }
    state[k] = list;
  }
  return state;
}
