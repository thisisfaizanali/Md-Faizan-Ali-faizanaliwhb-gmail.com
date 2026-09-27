import React, { useState } from 'react';
import { api } from '../api.js';
import { Gated, ErrorNote } from '../ui.jsx';

// Rename and delete, each present only when the server allows it.
export function Admin({ org, permissions, onRenamed, onDeleted }) {
  const [mode, setMode] = useState(null); // null | 'rename' | 'confirm-delete'
  const [error, setError] = useState(null);

  const attempt = async (action) => {
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err);
    }
  };

  const rename = (e) => {
    e.preventDefault();
    const name = new FormData(e.currentTarget).get('name');
    attempt(async () => {
      await api('PATCH', `/orgs/${org.id}`, { name });
      setMode(null);
      await onRenamed();
    });
  };

  return (
    <section>
      <h2>Admin</h2>
      <ErrorNote error={error} />
      {mode === 'rename' ? (
        <form className="inline" onSubmit={rename}>
          <input name="name" defaultValue={org.name} aria-label="Organization name" />
          <button type="submit">Save</button>
          <button type="button" onClick={() => setMode(null)}>Cancel</button>
        </form>
      ) : (
        <Gated permissions={permissions} perm="org:update" data-testid="rename-org" onClick={() => setMode('rename')}>
          Rename organization
        </Gated>
      )}
      {mode === 'confirm-delete' ? (
        <p className="inline">
          Delete {org.name}? Every live session in it ends.
          <button type="button" className="danger" onClick={() => attempt(async () => {
            await api('DELETE', `/orgs/${org.id}`);
            await onDeleted();
          })}>
            Delete
          </button>
          <button type="button" onClick={() => setMode(null)}>Cancel</button>
        </p>
      ) : (
        <Gated permissions={permissions} perm="org:delete" data-testid="delete-org" className="danger" onClick={() => setMode('confirm-delete')}>
          Delete organization
        </Gated>
      )}
    </section>
  );
}
