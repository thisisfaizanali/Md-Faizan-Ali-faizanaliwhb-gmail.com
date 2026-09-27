// The one door to the API. The access token lives in this module's memory and nowhere
// else; the refresh token is an httpOnly cookie this code never sees.

let token = null;
let currentOrgId = null;
let refreshing = null;
let onSession = () => {};

export class ApiError extends Error {
  constructor({ status = 0, code, reason = null, message }) {
    super(message);
    this.status = status;
    this.code = code;
    this.reason = reason;
  }
}

// Called with every new auth shape (login, refresh, switch), so the app can re-render.
export function subscribe(fn) {
  onSession = fn;
}

function adopt(shape) {
  token = shape.token;
  currentOrgId = shape.org.id;
  onSession(shape);
  return shape;
}

async function send(method, path, body, { auth = true } = {}) {
  const headers = {};
  if (auth && token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers['content-type'] = 'application/json';

  let res;
  try {
    res = await fetch(`/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError({ code: 'NETWORK', message: "Can't reach the server." });
  }

  const text = await res.text();
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      throw new ApiError({ status: res.status, code: 'BAD_RESPONSE', message: `The server sent an unreadable response (${res.status}).` });
    }
  }
  if (!res.ok) {
    const e = json?.error;
    throw new ApiError({
      status: res.status,
      code: e?.code ?? 'BAD_RESPONSE',
      reason: e?.reason ?? null,
      message: e?.message ?? `Request failed (${res.status}).`,
    });
  }
  return json;
}

// At most one refresh in flight: two refreshes with one cookie would be a replay, which
// revokes the whole token family. This also covers StrictMode running the boot effect twice.
export function refresh(orgId = currentOrgId) {
  refreshing ??= send('POST', '/auth/refresh', orgId ? { orgId } : {}, { auth: false })
    .then(adopt)
    .finally(() => { refreshing = null; });
  return refreshing;
}

// Authenticated request. A stale token (permissions changed) is refreshed once and retried.
export async function api(method, path, body) {
  try {
    return await send(method, path, body);
  } catch (err) {
    if (err.status !== 401 || err.code !== 'TOKEN_STALE') throw err;
    await refresh(currentOrgId);
    return send(method, path, body);
  }
}

export const publicApi = (method, path, body) => send(method, path, body, { auth: false });

export async function login(email, password) {
  return adopt(await send('POST', '/auth/login', { email, password }, { auth: false }));
}

export async function switchOrg(orgId) {
  return adopt(await api('POST', '/auth/token', { orgId }));
}

// Re-read the auth shape (e.g. after renaming the org) without minting a new token.
export async function reloadSession() {
  const me = await api('GET', '/auth/me');
  onSession({ ...me, token });
  return me;
}

export async function logout() {
  try {
    await send('POST', '/auth/logout', undefined, { auth: false });
  } finally {
    token = null;
    currentOrgId = null;
  }
}
