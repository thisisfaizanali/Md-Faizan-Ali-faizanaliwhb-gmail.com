import React, { useState } from 'react';
import { api, switchOrg, refresh, reloadSession, logout } from './api.js';
import { allowed, ErrorNote } from './ui.jsx';
import { Devices } from './views/Devices.jsx';
import { Grants } from './views/Grants.jsx';
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
  const { org, orgs, role, permissions, user } = session;
  // Each card is present under the first of its permissions the server allows.
  const cards = CARDS
    .map((c) => ({ ...c, perm: c.perms.find((p) => allowed(permissions, p)) }))
    .filter((c) => c.perm);
  const [view, setView] = useState(() => (cards.some((c) => c.key === 'devices') ? 'devices' : cards[0]?.key ?? null));
  const [error, setError] = useState(null);
  const [creating, setCreating] = useState(false);

  const attempt = async (action) => {
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err);
    }
  };

  const createOrg = (e) => {
    e.preventDefault();
    const name = new FormData(e.currentTarget).get('name');
    attempt(async () => {
      const created = await api('POST', '/orgs', { name });
      setCreating(false);
      await switchOrg(created.id);
    });
  };

  const signOut = () => attempt(async () => {
    await logout();
    onSignedOut();
  });

  // After deleting the active org, land in the earliest remaining one, or sign out.
  const afterDelete = async () => {
    try {
      await refresh(null);
    } catch {
      await logout();
      onSignedOut();
    }
  };

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
            onClick={() => o.id !== org.id && attempt(() => switchOrg(o.id))}>
            {o.name}
          </button>
        ))}
        {creating ? (
          <form className="inline" onSubmit={createOrg}>
            <input name="name" placeholder="New organization name" aria-label="New organization name" autoFocus />
            <button type="submit">Create</button>
            <button type="button" onClick={() => setCreating(false)}>Cancel</button>
          </form>
        ) : (
          <button type="button" data-testid="create-org" onClick={() => setCreating(true)}>New organization</button>
        )}
      </nav>

      <ErrorNote error={error} />

      <div className="body">
        <nav className="cards" aria-label="Sections">
          {cards.map((c) => (
            <button key={c.key} type="button" data-testid={`nav-${c.key}`} data-permission={c.perm} data-state="unlocked"
              aria-current={view === c.key ? 'page' : undefined} onClick={() => setView(c.key)}>
              {c.label}
            </button>
          ))}
        </nav>
        <main className="content">
          {view === 'devices' && <Devices orgId={org.id} permissions={permissions} />}
          {view === 'grants' && <Grants orgId={org.id} permissions={permissions} />}
          {view === 'admin' && (
            <Admin org={org} permissions={permissions} onRenamed={reloadSession} onDeleted={afterDelete} />
          )}
          {['people', 'sessions', 'audit'].includes(view) && (
            <section><h2>{CARDS.find((c) => c.key === view).label}</h2><p>This view is not built yet.</p></section>
          )}
          {view === null && <p>You have no sections available in this organization.</p>}
        </main>
      </div>
    </div>
  );
}
