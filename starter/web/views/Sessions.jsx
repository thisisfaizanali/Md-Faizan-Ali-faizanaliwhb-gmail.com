import React, { useCallback, useState } from 'react';
import { api } from '../api.js';
import { Gated, ErrorNote, Notice, useResource, attempt, allowed, formValue, when } from '../ui.jsx';

const MODES = ['view', 'control', 'terminal']; // the API's session modes

export function Sessions({ orgId, me, permissions, report }) {
  const [notice, setNotice] = useState(null);
  const [formOpen, setFormOpen] = useState(false);
  const loadSessions = useCallback(() => api('GET', `/orgs/${orgId}/sessions`).then((b) => b.sessions), [orgId]);
  const loadDevices = useCallback(
    () => (allowed(permissions, 'device:list') ? api('GET', `/orgs/${orgId}/devices`).then((b) => b.devices) : Promise.resolve([])),
    [orgId, permissions],
  );
  const [sessions, reload] = useResource(loadSessions, report);
  const [devices] = useResource(loadDevices, report);
  const deviceName = (id) => devices?.find((d) => d.id === id)?.name ?? id;

  const stop = async (id) => {
    report(null);
    setNotice(null);
    const r = await attempt(() => api('DELETE', `/sessions/${id}`), report);
    if (r.ok) {
      setNotice(`Session ended (${r.value.end_reason}).`);
      reload();
    }
  };

  return (
    <section>
      <header className="view-head">
        <h2>Sessions</h2>
        {!formOpen && (
          <Gated permissions={permissions} perm="session:start" data-testid="new-session" onClick={() => setFormOpen(true)}>
            Start a session
          </Gated>
        )}
      </header>
      {formOpen && (
        <NewSession orgId={orgId} devices={devices ?? []} onCancel={() => setFormOpen(false)}
          onStarted={(s) => { setFormOpen(false); setNotice(`Started a ${s.mode} session (${s.id}).`); reload(); }} />
      )}
      <Notice>{notice}</Notice>
      {sessions?.length === 0 && <p>No sessions yet.</p>}
      {sessions?.length > 0 && (
        <table>
          <thead>
            <tr><th>Device</th><th>User</th><th>Mode</th><th>State</th><th>Started</th><th>Expires</th><th>Ended because</th><th /></tr>
          </thead>
          <tbody>
            {sessions.map((s) => {
              const active = s.state !== 'ended';
              const mine = s.user_id === me;
              return (
                <tr key={s.id} data-testid="session-row" data-session-id={s.id}>
                  <td>{deviceName(s.device_id)}</td>
                  <td>{mine ? 'you' : s.user_id}</td>
                  <td>{s.mode}</td>
                  <td>{s.state}</td>
                  <td>{when(s.started_at)}</td>
                  <td>{when(s.expires_at)}</td>
                  <td>{s.end_reason ?? '—'}</td>
                  <td>
                    {/* Stopping your own session is not permission-gated; stopping anyone
                        else's is session:terminate. */}
                    {active && mine && <button type="button" data-testid="stop-session" onClick={() => stop(s.id)}>Stop</button>}
                    {active && !mine && (
                      <Gated permissions={permissions} perm="session:terminate" data-testid="stop-session" onClick={() => stop(s.id)}>
                        Stop
                      </Gated>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

function NewSession({ orgId, devices, onCancel, onStarted }) {
  const [error, setError] = useState(null);
  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    const body = { deviceId: formValue(e.currentTarget, 'deviceId'), mode: formValue(e.currentTarget, 'mode') };
    const r = await attempt(() => api('POST', `/orgs/${orgId}/sessions`, body), setError);
    if (r.ok) onStarted(r.value);
  };
  return (
    <form className="inline" onSubmit={submit}>
      <select name="deviceId" aria-label="Device">
        {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
      </select>
      <select name="mode" aria-label="Mode">
        {MODES.map((m) => <option key={m} value={m}>{m}</option>)}
      </select>
      <button type="submit">Start</button>
      <button type="button" onClick={onCancel}>Cancel</button>
      {/* DEVICE_BUSY's message names the holder's session. */}
      <ErrorNote error={error} />
    </form>
  );
}
