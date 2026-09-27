import React, { useState } from 'react';
import { api } from '../api.js';
import { Gated, ErrorNote, attempt, formValue } from '../ui.jsx';

// Rename and delete, each present only when the server allows it.
export function Admin({ org, permissions, report, onRenamed, onDeleted }) {
  const [mode, setMode] = useState(null); // null | 'rename' | 'confirm-delete'
  const [renameError, setRenameError] = useState(null);

  const rename = async (e) => {
    e.preventDefault();
    setRenameError(null);
    const name = formValue(e.currentTarget, 'name');
    const r = await attempt(() => api('PATCH', `/orgs/${org.id}`, { name }), setRenameError);
    if (r.ok) {
      setMode(null);
      await onRenamed();
    }
  };

  const remove = async () => {
    report(null);
    const r = await attempt(() => api('DELETE', `/orgs/${org.id}`), report);
    if (r.ok) await onDeleted();
  };

  return (
    <section>
      <h2>Admin</h2>
      <div className="stack">
        {mode === 'rename' ? (
          <form className="inline" onSubmit={rename}>
            <input name="name" defaultValue={org.name} aria-label="Organization name" />
            <button type="submit">Save</button>
            <button type="button" onClick={() => setMode(null)}>Cancel</button>
            <ErrorNote error={renameError} />
          </form>
        ) : (
          <Gated permissions={permissions} perm="org:update" data-testid="rename-org" onClick={() => setMode('rename')}>
            Rename organization
          </Gated>
        )}
        {mode === 'confirm-delete' ? (
          <p className="inline">
            Delete {org.name}? Every live session in it ends.
            <button type="button" className="danger" onClick={remove}>Delete</button>
            <button type="button" onClick={() => setMode(null)}>Cancel</button>
          </p>
        ) : (
          <Gated permissions={permissions} perm="org:delete" data-testid="delete-org" className="danger" onClick={() => setMode('confirm-delete')}>
            Delete organization
          </Gated>
        )}
      </div>
    </section>
  );
}
