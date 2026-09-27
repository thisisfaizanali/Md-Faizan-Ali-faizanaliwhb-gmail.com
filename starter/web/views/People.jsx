import React, { useCallback, useState } from 'react';
import { api } from '../api.js';
import { Gated, ErrorNote, Notice, useResource, attempt, allowed, formValue, when } from '../ui.jsx';

// Entries are present by the org-level permission on every row. The rank rules live on the
// server; when it refuses, its message is shown.
export function People({ orgId, me, permissions, assignableRoles, report, onLeft }) {
  const [notice, setNotice] = useState(null);
  const loadMembers = useCallback(() => api('GET', `/orgs/${orgId}/members`).then((b) => b.members), [orgId]);
  const [members, reload] = useResource(loadMembers, report);

  const act = async (action, success) => {
    report(null);
    setNotice(null);
    const r = await attempt(action, report);
    if (r.ok) setNotice(success);
    reload(); // on failure too: a refused role change reverts to the server's value
    return r.ok;
  };

  const leave = async () => {
    report(null);
    const r = await attempt(() => api('DELETE', `/orgs/${orgId}/members/me`), report);
    if (r.ok) await onLeft();
  };

  return (
    <section>
      <header className="view-head">
        <h2>People</h2>
        <button type="button" className="danger" onClick={leave}>Leave organization</button>
      </header>
      <Notice>{notice}</Notice>
      {allowed(permissions, 'user:invite') && (
        <Invites orgId={orgId} permissions={permissions} assignableRoles={assignableRoles} report={report} />
      )}
      {members === null && <p>Loading members…</p>}
      {members?.length > 0 && (
        <table>
          <thead>
            <tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th /></tr>
          </thead>
          <tbody>
            {members.map((m) => (
              <MemberRow key={m.userId} orgId={orgId} member={m} isMe={m.userId === me}
                permissions={permissions} assignableRoles={assignableRoles} act={act} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function MemberRow({ orgId, member, isMe, permissions, assignableRoles, act }) {
  const [confirmRemove, setConfirmRemove] = useState(false);
  const path = `/orgs/${orgId}/members/${member.userId}`;
  // The member's current role stays selectable even when the caller could not assign it.
  const options = assignableRoles.some((r) => r.key === member.role)
    ? assignableRoles
    : [{ key: member.role, label: member.role }, ...assignableRoles];
  const suspended = member.status === 'suspended';

  return (
    <tr data-testid="user-row" data-user-id={member.userId}>
      <td>{member.name}{isMe && ' (you)'}</td>
      <td>{member.email}</td>
      <td>
        {allowed(permissions, 'user:role:update') ? (
          <select value={member.role} aria-label={`Role for ${member.name}`}
            data-testid="role-select" data-permission="user:role:update" data-state="unlocked"
            onChange={(e) => act(() => api('PATCH', path, { role: e.target.value }), `Role changed to ${e.target.value}.`)}>
            {options.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
          </select>
        ) : member.role}
      </td>
      <td>{member.status}</td>
      <td>
        <div className="actions">
          <Gated permissions={permissions} perm="user:remove" data-testid="suspend-user"
            onClick={() => act(() => api(suspended ? 'DELETE' : 'POST', `${path}/suspend`), suspended ? 'Member reinstated.' : 'Member suspended.')}>
            {suspended ? 'Reinstate' : 'Suspend'}
          </Gated>
          {confirmRemove ? (
            <span className="inline">
              Remove {member.name}?
              <button type="button" className="danger" onClick={() => act(() => api('DELETE', path), 'Member removed.')}>Confirm</button>
              <button type="button" onClick={() => setConfirmRemove(false)}>Cancel</button>
            </span>
          ) : (
            <Gated permissions={permissions} perm="user:remove" data-testid="remove-user" onClick={() => setConfirmRemove(true)}>
              Remove
            </Gated>
          )}
        </div>
      </td>
    </tr>
  );
}

function Invites({ orgId, permissions, assignableRoles, report }) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState(null);
  const [link, setLink] = useState(null);
  const loadInvites = useCallback(() => api('GET', `/orgs/${orgId}/invites`).then((b) => b.invites), [orgId]);
  const [invites, reload] = useResource(loadInvites, report);

  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    const body = { email: formValue(e.currentTarget, 'email'), role: formValue(e.currentTarget, 'role') };
    const r = await attempt(() => api('POST', `/orgs/${orgId}/invites`, body), setError);
    if (r.ok) {
      setOpen(false);
      setLink(`${window.location.origin}/invite/${r.value.inviteToken}`);
      reload();
    }
  };

  const cancel = async (id) => {
    report(null);
    const r = await attempt(() => api('DELETE', `/orgs/${orgId}/invites/${id}`), report);
    if (r.ok) reload();
  };

  return (
    <div className="invites">
      {open ? (
        <form className="inline" onSubmit={submit}>
          <input name="email" type="email" placeholder="Email" aria-label="Invitee email" />
          <select name="role" aria-label="Role">
            {assignableRoles.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
          </select>
          <button type="submit">Send invite</button>
          <button type="button" onClick={() => setOpen(false)}>Cancel</button>
          <ErrorNote error={error} />
        </form>
      ) : (
        <Gated permissions={permissions} perm="user:invite" data-testid="invite-user" onClick={() => { setLink(null); setOpen(true); }}>
          Invite someone
        </Gated>
      )}
      {link && (
        <div className="notice" role="status">
          <p>Invite link — copy it now, it won't be shown again:</p>
          <code className="link">{link}</code>{' '}
          <button type="button" onClick={() => navigator.clipboard?.writeText(link)}>Copy</button>
        </div>
      )}
      {invites?.length > 0 && (
        <table>
          <thead><tr><th>Invited</th><th>Role</th><th>Status</th><th>Expires</th><th /></tr></thead>
          <tbody>
            {invites.map((i) => (
              <tr key={i.id}>
                <td>{i.email}</td>
                <td>{i.role}</td>
                <td>{i.status}</td>
                <td>{when(i.expiresAt)}</td>
                <td><button type="button" onClick={() => cancel(i.id)}>Cancel invite</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
