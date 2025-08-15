export function authFetch(input, init={}) {
  const token = localStorage.getItem('lotus_token');
  const headers = new Headers(init.headers || {});
  if (token) headers.set('Authorization', `Bearer ${token}`);
  headers.set('Cache-Control','no-store');
  return fetch(input, { ...init, headers });
}
export function getMyShops() {
  try { return JSON.parse(localStorage.getItem('lotus_shops') || '[]'); }
  catch { return []; }
}
export function requireLogin() {
  if (!localStorage.getItem('lotus_token')) location.href = '/login.html';
}
