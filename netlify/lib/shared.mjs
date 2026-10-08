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
