import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { Gated, ErrorNote, Notice } from '../ui.jsx';

// M7a: the list and revoke. The create form is M7b.
export function Grants({ orgId, permissions }) {
  const [grants, setGrants] = useState(null);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);

  const load = useCallback(() => {
    let live = true;
    api('GET', `/orgs/${orgId}/grants`)
      .then((body) => live && setGrants(body.grants))
      .catch((err) => live && setError(err));
    return () => { live = false; };
  }, [orgId]);
  useEffect(load, [load]);

  async function revoke(id) {
    setError(null);
    setNotice(null);
    try {
      await api('DELETE', `/orgs/${orgId}/grants/${id}`);
      setNotice('Grant revoked.');
      load();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <section>
      <header className="view-head">
        <h2>Grants</h2>
        <Gated permissions={permissions} perm="grant:create" data-testid="new-grant"
          onClick={() => setNotice('Creating grants from the console is not built yet.')}>
          New grant
        </Gated>
      </header>
      <ErrorNote error={error} />
      <Notice>{notice}</Notice>
      {grants?.length === 0 && <p>No grants in this organization.</p>}
      {grants?.length > 0 && (
        <table>
          <thead>
            <tr><th>User</th><th>Effect</th><th>Permissions</th><th>Scope</th><th>Status</th><th /></tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id} data-testid="grant-row" data-grant-id={g.id} data-effect={g.effect}>
                <td>{g.userId}</td>
                <td>{g.effect}</td>
                <td>{g.permissions.join(', ')}</td>
                <td>{g.deviceId ?? 'org-wide'}</td>
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
