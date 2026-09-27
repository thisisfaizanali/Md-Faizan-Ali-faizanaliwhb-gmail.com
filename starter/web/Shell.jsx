import React, { useCallback, useState } from 'react';
import { api, switchOrg, refresh, reloadSession, logout } from './api.js';
import { allowed, ErrorNote, attempt } from './ui.jsx';
import { Devices } from './views/Devices.jsx';
import { People } from './views/People.jsx';
import { Grants } from './views/Grants.jsx';
import { Sessions } from './views/Sessions.jsx';
import { Audit } from './views/Audit.jsx';
import { Admin } from './views/Admin.jsx';

// Each card and the permission that governs it (UI-INVENTORY.md §2). This maps UI to
// permission keys; whether a key is held is always the server's answer.
const CARDS = [
  { key: 'devices', label: 'Devices', perms: ['device:list'] },
  { key: 'people', label: 'People', perms: ['user:read'] },
  { key: 'grants', label: 'Grants', perms: ['user:read'] },
  { key: 'sessions', label: 'Sessions', perms: ['session:view'] },
  { key: 'audit', label: 'Audit', perms: ['audit:read'] },
  { key: 'admin', label: 'Admin', perms: ['org:update', 'org:delete'] },
];

const PALETTE = new Set(['cobalt', 'ember', 'jade', 'violet', 'amber', 'slate']);

// A theme outside the palette still gets its own stable colour.
function hashedColour(theme) {
  let h = 0;
  for (const ch of theme) h = (h * 31 + ch.codePointAt(0)) >>> 0;
  return `hsl(${h % 360} 45% 94%)`;
}

export function Shell({ session, onSignedOut }) {
  const { org, orgs, role, permissions, user, assignableRoles } = session;
  // Each card is present under the first of its permissions the server allows.
  const cards = CARDS
    .map((c) => ({ ...c, perm: c.perms.find((p) => allowed(permissions, p)) }))
    .filter((c) => c.perm);
  const [view, setView] = useState(() => (cards.some((c) => c.key === 'devices') ? 'devices' : cards[0]?.key ?? null));
  // The one banner for failures outside a form.
  const [requestError, setRequestError] = useState(null);
  const report = useCallback((err) => setRequestError(err), []);

  const open = (key) => {
    setRequestError(null);
    setView(key);
  };

  // The shipped UI test answers a prompt here, so the mechanism is fixed.
  const createOrg = async () => {
    const name = window.prompt('Name for the new organization');
    if (!name?.trim()) return;
    report(null);
    await attempt(async () => {
      const created = await api('POST', '/orgs', { name });
      await switchOrg(created.id);
    }, report);
  };

  const signOut = async () => {
    report(null);
    const r = await attempt(logout, report);
    if (r.ok) onSignedOut();
  };

  // After deleting or leaving the active org, land in the earliest remaining one, or sign out.
  const landElsewhere = async () => {
    try {
      await refresh(null);
    } catch {
      await attempt(logout, () => {});
      onSignedOut();
    }
  };

  const common = { orgId: org.id, me: user.id, permissions, report };
  const themeStyle = PALETTE.has(org.theme) ? undefined : { '--org-bg': hashedColour(org.theme) };

  return (
    <div className="shell" data-testid="app-shell" data-org-id={org.id} data-org-theme={org.theme} style={themeStyle}>
      <header className="topbar">
        <div>
          <strong className="org-name">{org.name}</strong>
          <span className="role">Role: <span data-testid="active-role">{role}</span></span>
        </div>
        <div className="who">
          {user.email}
          <button type="button" data-testid="sign-out" onClick={signOut}>Sign out</button>
        </div>
      </header>

      <nav className="orgs" aria-label="Organizations">
        {orgs.map((o) => (
          <button key={o.id} type="button" data-testid="org-option" data-org-id={o.id}
            aria-current={o.id === org.id ? 'true' : undefined}
            onClick={() => o.id !== org.id && attempt(() => switchOrg(o.id), report)}>
            {o.name}
          </button>
        ))}
        <button type="button" data-testid="create-org" onClick={createOrg}>New organization</button>
      </nav>

      <div className="banner">
        <ErrorNote error={requestError} testId="request-error" />
      </div>

      <div className="body">
        <nav className="cards" aria-label="Sections">
          {cards.map((c) => (
            <button key={c.key} type="button" data-testid={`nav-${c.key}`} data-permission={c.perm} data-state="unlocked"
              aria-current={view === c.key ? 'page' : undefined} onClick={() => open(c.key)}>
              {c.label}
            </button>
          ))}
        </nav>
        <main className="content">
          {view === 'devices' && <Devices {...common} />}
          {view === 'people' && <People {...common} assignableRoles={assignableRoles} onLeft={landElsewhere} />}
          {view === 'grants' && <Grants {...common} />}
          {view === 'sessions' && <Sessions {...common} />}
          {view === 'audit' && <Audit {...common} />}
          {view === 'admin' && (
            <Admin org={org} permissions={permissions} report={report} onRenamed={reloadSession} onDeleted={landElsewhere} />
          )}
          {view === null && <p>You have no sections available in this organization.</p>}
        </main>
      </div>
    </div>
  );
}
