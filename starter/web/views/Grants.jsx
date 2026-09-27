import React, { useCallback, useState } from 'react';
import { api } from '../api.js';
import { Gated, ErrorNote, Notice, useResource, attempt, allowed } from '../ui.jsx';

export function Grants({ orgId, me, permissions, report }) {
  const [notice, setNotice] = useState(null);
  const [formOpen, setFormOpen] = useState(false);

  const loadGrants = useCallback(() => api('GET', `/orgs/${orgId}/grants`).then((b) => b.grants), [orgId]);
  const loadMembers = useCallback(() => api('GET', `/orgs/${orgId}/members`).then((b) => b.members), [orgId]);
  // Device names only when the caller may list them; otherwise ids are shown.
  const loadDevices = useCallback(
    () => (allowed(permissions, 'device:list') ? api('GET', `/orgs/${orgId}/devices`).then((b) => b.devices) : Promise.resolve([])),
    [orgId, permissions],
  );
  const [grants, reloadGrants] = useResource(loadGrants, report);
  const [members] = useResource(loadMembers, report);
  const [devices] = useResource(loadDevices, report);

  const nameOf = (userId) => members?.find((m) => m.userId === userId)?.name ?? userId;
  const deviceOf = (id) => (id ? devices?.find((d) => d.id === id)?.name ?? id : 'Whole org');

  async function revoke(id) {
    report(null);
    setNotice(null);
    const r = await attempt(() => api('DELETE', `/orgs/${orgId}/grants/${id}`), report);
    if (r.ok) {
      setNotice('Grant revoked.');
      reloadGrants();
    }
  }

  return (
    <section>
      <header className="view-head">
        <h2>Grants</h2>
        {!formOpen && (
          <Gated permissions={permissions} perm="grant:create" data-testid="new-grant" onClick={() => setFormOpen(true)}>
            New grant
          </Gated>
        )}
      </header>
      {formOpen && (
        <GrantForm
          orgId={orgId}
          me={me}
          members={members ?? []}
          devices={devices ?? []}
          catalogue={Object.keys(permissions)}
          onCancel={() => setFormOpen(false)}
          onCreated={() => { setFormOpen(false); setNotice('Grant created.'); reloadGrants(); }}
        />
      )}
      <Notice>{notice}</Notice>
      {grants?.length === 0 && <p>No grants in this organization.</p>}
      {grants?.length > 0 && (
        <table>
          <thead>
            <tr><th>User</th><th>Device</th><th>Effect</th><th>Permissions</th><th>Status</th><th /></tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id} data-testid="grant-row" data-grant-id={g.id} data-effect={g.effect}>
                <td>{nameOf(g.userId)}</td>
                <td>{deviceOf(g.deviceId)}</td>
                <td>{g.effect}</td>
                <td>{g.permissions.join(', ')}</td>
                <td>{g.status}</td>
                <td>
                  <Gated permissions={permissions} perm="grant:revoke" data-testid="revoke-grant" onClick={() => revoke(g.id)}>
                    Revoke
                  </Gated>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

// The catalogue comes from the auth shape's permission keys, so undocumented permissions
// appear too. Wildcards (device:*) go in the free-text field; the server validates them.
function GrantForm({ orgId, me, members, devices, catalogue, onCancel, onCreated }) {
  const [error, setError] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    const form = new FormData(e.currentTarget);
    const patterns = String(form.get('patterns') ?? '').split(/[\s,]+/).filter(Boolean);
    const expires = String(form.get('expiresAt') ?? '');
    const body = {
      userId: form.get('userId'),
      effect: form.get('effect'),
      permissions: [...form.getAll('permission').map(String), ...patterns],
      ...(form.get('deviceId') ? { deviceId: form.get('deviceId') } : {}),
      ...(expires ? { expiresAt: new Date(expires).toISOString() } : {}),
    };
    const r = await attempt(() => api('POST', `/orgs/${orgId}/grants`, body), setError);
    if (r.ok) onCreated();
  }

  return (
    <form className="card grant-form" onSubmit={submit}>
      <label>
        User
        <select name="userId" data-testid="grant-user">
          {members.filter((m) => m.userId !== me).map((m) => (
            <option key={m.userId} value={m.userId}>{m.name} ({m.email})</option>
          ))}
        </select>
      </label>
      <label>
        Device
        <select name="deviceId" data-testid="grant-device">
          <option value="">Whole org</option>
          {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
        </select>
      </label>
      <label>
        Effect
        <select name="effect" data-testid="grant-effect">
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
      </label>
      <fieldset>
        <legend>Permissions</legend>
        <div className="checks">
          {catalogue.map((key) => (
            <label key={key} className="check">
              <input type="checkbox" name="permission" value={key} data-permission-key={key} />
              {key}
            </label>
          ))}
        </div>
      </fieldset>
      <label>
        Wildcard patterns (optional, e.g. device:*)
        <input name="patterns" />
      </label>
      <label>
        Expires (optional)
        <input name="expiresAt" type="datetime-local" />
      </label>
      <ErrorNote error={error} testId="grant-error" />
      <div className="inline">
        <button type="submit" data-testid="grant-submit">Create grant</button>
        <button type="button" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}
