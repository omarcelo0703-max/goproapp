// Dice quién está conectado (la app lo usa al abrir para decidir si muestra el login).
import { currentUser, json, fail } from '../lib/shared.mjs';

export default async (req) => {
  if (req.method !== 'GET') return fail(405, 'Método no permitido');
  const u = await currentUser();
  if (!u) return fail(401, 'No autenticado');
  return json({ usuario: u.usuario, nombre: u.nombre, isAdmin: u.isAdmin });
};

export const config = { path: '/api/me' };
