import React, { useCallback, useState } from 'react';
import { api } from '../api.js';
import { Gated, ErrorNote, Notice, useResource, attempt, formValue } from '../ui.jsx';

// The row entries and the permission that governs each (UI-INVENTORY.md §3). Used for the
// buttons and for explaining the ones that are absent.
const ROW_ACTIONS = [
  { perm: 'device:view', testId: 'start-view', label: 'View', mode: 'view' },
  { perm: 'device:control', testId: 'start-control', label: 'Control', mode: 'control' },
  { perm: 'device:terminal', testId: 'start-terminal', label: 'Terminal', mode: 'terminal' },
  { perm: 'device:file_transfer', testId: 'transfer-files', label: 'Transfer files' },
  { perm: 'device:update', testId: 'rename-device', label: 'Rename' },
  { perm: 'device:provision', testId: 'decommission-device', label: 'Decommission' },
];

const WHY = { implicit: 'not granted', explicit_deny: 'denied by a grant', expired_grant: 'access expired' };

// Fetches on every mount: presence comes from the response, never from a cached copy.
export function Devices({ orgId, permissions, report }) {
  const [notice, setNotice] = useState(null);
  const load = useCallback(() => api('GET', `/orgs/${orgId}/devices`).then((b) => b.devices), [orgId]);
  const [devices, reload] = useResource(load, report);

  // Row actions report through the shell banner; success shows here and refetches.
  const run = async (action, success) => {
    report(null);
    setNotice(null);
    const r = await attempt(action, report);
    if (r.ok) {
      setNotice(success(r.value));
      reload();
    }
  };

  return (
    <section>
      <header className="view-head">
        <h2>Devices</h2>
        <AddDevice orgId={orgId} permissions={permissions} onAdded={(d) => { setNotice(`Added ${d.name}.`); reload(); }} />
      </header>
      <Notice>{notice}</Notice>
      {devices === null && <p>Loading devices…</p>}
      {devices?.length === 0 && <p data-testid="devices-empty">No devices in this organization yet.</p>}
      {devices?.length > 0 && (
        <table>
          <thead>
            <tr><th>Name</th><th>Kind</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <DeviceRow key={d.id} orgId={orgId} device={d} run={run} setNotice={setNotice} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function AddDevice({ orgId, permissions, onAdded }) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState(null);
  if (!open) {
    return (
      <Gated permissions={permissions} perm="device:provision" data-testid="add-device" onClick={() => setOpen(true)}>
        Add device
      </Gated>
    );
  }
  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    const body = { name: formValue(e.currentTarget, 'name'), kind: formValue(e.currentTarget, 'kind') };
    const r = await attempt(() => api('POST', `/orgs/${orgId}/devices`, body), setError);
    if (r.ok) {
      setOpen(false);
      onAdded(r.value);
    }
  };
  return (
    <form className="inline" onSubmit={submit}>
      <input name="name" placeholder="Device name" aria-label="Device name" />
      {/* The kind list lives in the database; the server says if a value is not allowed. */}
      <input name="kind" placeholder="Kind, e.g. linux" aria-label="Device kind" />
      <button type="submit">Add</button>
      <button type="button" onClick={() => setOpen(false)}>Cancel</button>
      <ErrorNote error={error} />
    </form>
  );
}

function DeviceRow({ orgId, device, run, setNotice }) {
  const [mode, setMode] = useState(null); // null | 'rename' | 'confirm-decommission'
  const p = device.permissions;
  const path = `/orgs/${orgId}/devices/${device.id}`;

  const handlers = {
    'start-view': () => start('view'),
    'start-control': () => start('control'),
    'start-terminal': () => start('terminal'),
    'transfer-files': () => setNotice('File transfer is out of scope — sessions here are records.'),
    'rename-device': () => setMode('rename'),
    'decommission-device': () => setMode('confirm-decommission'),
  };
  const start = (m) => run(
    () => api('POST', `/orgs/${orgId}/sessions`, { deviceId: device.id, mode: m }),
    (s) => `Started a ${s.mode} session on ${device.name} (${s.id}).`,
  );
  const rename = (e) => {
    e.preventDefault();
    const name = formValue(e.currentTarget, 'name');
    run(() => api('PATCH', path, { name }), (d) => { setMode(null); return `Renamed to ${d.name}.`; });
  };
  const decommission = () => run(() => api('DELETE', path), () => `Decommissioned ${device.name}.`);

  const denied = ROW_ACTIONS.filter((a) => p[a.perm]?.effect !== 'allow');

  return (
    <tr data-testid="device-row" data-device-id={device.id}>
      <td>{device.name}</td>
      <td>{device.kind}</td>
      <td>{device.online ? 'Online' : 'Offline'}</td>
      <td>
        <div className="actions">
          {ROW_ACTIONS.map((a) => (
            <Gated key={a.testId} permissions={p} perm={a.perm} data-testid={a.testId} onClick={handlers[a.testId]}>
              {a.label}
            </Gated>
          ))}
        </div>
        {mode === 'rename' && (
          <form className="inline" onSubmit={rename}>
            <input name="name" defaultValue={device.name} aria-label="New device name" />
            <button type="submit">Save</button>
            <button type="button" onClick={() => setMode(null)}>Cancel</button>
          </form>
        )}
        {mode === 'confirm-decommission' && (
          <span className="inline">
            Decommission {device.name}? Its sessions end.
            <button type="button" className="danger" onClick={decommission}>Confirm</button>
            <button type="button" onClick={() => setMode(null)}>Cancel</button>
          </span>
        )}
        {denied.length > 0 && (
          <details className="why">
            <summary>Why can't I…</summary>
            <ul>
              {denied.map((a) => (
                <li key={a.perm}>{a.label}: {WHY[p[a.perm]?.reason] ?? 'not available'}</li>
              ))}
            </ul>
          </details>
        )}
      </td>
    </tr>
  );
}
