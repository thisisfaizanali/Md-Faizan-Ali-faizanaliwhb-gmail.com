// Route registration. The router is deliberately tiny: createRouter() from
// ../router.js, first match wins, so register specific paths before parameterised
// ones ('/members/me' before '/members/:userId').
//
// Every handler is wrapped once so a 403 in a known org is audited as a denial,
// with the route as the action. Success rows are written by the handlers themselves.

import { auditDenials } from '../audit.js';
import { registerAuthRoutes } from './auth.js';
import { registerOrgRoutes } from './orgs.js';
import { registerInviteRoutes } from './invites.js';
import { registerDeviceRoutes } from './devices.js';
import { registerSessionRoutes } from './sessions.js';

export function registerRoutes(router, deps) {
  const { db } = deps;
  const guard = (method, pattern, handler) => (ctx, params, res) =>
    auditDenials(db, ctx, { action: `${method} ${pattern}`, targetType: null, targetId: null },
      () => handler(ctx, params, res));

  const r = Object.fromEntries(['get', 'post', 'patch', 'delete'].map((m) =>
    [m, (pattern, handler) => router[m](pattern, guard(m.toUpperCase(), pattern, handler))]));

  registerAuthRoutes(r, deps);
  registerOrgRoutes(r, deps);
  registerInviteRoutes(r, deps);
  registerDeviceRoutes(r, deps);
  registerSessionRoutes(r, deps);
}
