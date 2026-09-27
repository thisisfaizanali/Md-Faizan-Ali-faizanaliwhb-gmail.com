import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';
import { Gated, ErrorNote, Notice } from '../ui.jsx';

const START_MODES = [
  { mode: 'view', perm: 'device:view', testId: 'start-view', label: 'View' },
  { mode: 'control', perm: 'device:control', testId: 'start-control', label: 'Control' },
  { mode: 'terminal', perm: 'device:terminal', testId: 'start-terminal', label: 'Terminal' },
];

// Fetches on every mount: presence comes from the response, never from a cached copy.
export function Devices({ orgId, permissions }) {
  const [devices, setDevices] = useState(null);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);

  const load = useCallback(() => {
    let live = true;
    api('GET', `/orgs/${orgId}/devices`)
      .then((body) => live && setDevices(body.devices))
      .catch((err) => live && setError(err));
    return () => { live = false; };
  }, [orgId]);
  useEffect(load, [load]);

  // Every action reports its outcome: the server's message on failure.
  const run = async (action, success) => {
    setError(null);
    setNotice(null);
    try {
      const result = await action();
      setNotice(success(result));
      load();
    } catch (err) {
      setError(err);
    }
  };

  return (
    <section>
      <header className="view-head">
        <h2>Devices</h2>
        <AddDevice orgId={orgId} permissions={permissions} run={run} />
      </header>
      <ErrorNote error={error} />
      <Notice>{notice}</Notice>
      {devices === null && !error && <p>Loading devices…</p>}
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

function AddDevice({ orgId, permissions, run }) {
  const [open, setOpen] = useState(false);
  if (!open) {
    return (
      <Gated permissions={permissions} perm="device:provision" data-testid="add-device" onClick={() => setOpen(true)}>
        Add device
      </Gated>
    );
  }
  const submit = (e) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    run(
      () => api('POST', `/orgs/${orgId}/devices`, { name: form.get('name'), kind: String(form.get('kind')).trim() }),
      (d) => { setOpen(false); return `Added ${d.name}.`; },
    );
  };
  return (
    <form className="inline" onSubmit={submit}>
      <input name="name" placeholder="Device name" aria-label="Device name" />
      {/* The kind list lives in the database; the server says if a value is not allowed. */}
      <input name="kind" placeholder="Kind, e.g. linux" aria-label="Device kind" />
      <button type="submit">Add</button>
      <button type="button" onClick={() => setOpen(false)}>Cancel</button>
    </form>
  );
}

function DeviceRow({ orgId, device, run, setNotice }) {
  const [mode, setMode] = useState(null); // null | 'rename' | 'confirm-decommission'
  const p = device.permissions;

  const start = (m) => run(
    () => api('POST', `/orgs/${orgId}/sessions`, { deviceId: device.id, mode: m }),
    (s) => `Started a ${s.mode} session on ${device.name} (${s.id}).`,
  );

  const rename = (e) => {
    e.preventDefault();
    const name = new FormData(e.currentTarget).get('name');
    run(() => api('PATCH', `/orgs/${orgId}/devices/${device.id}`, { name }), (d) => `Renamed to ${d.name}.`);
  };

  const decommission = () => run(
    () => api('DELETE', `/orgs/${orgId}/devices/${device.id}`),
    () => `Decommissioned ${device.name}.`,
  );

  return (
    <tr data-testid="device-row" data-device-id={device.id}>
      <td>{device.name}</td>
      <td>{device.kind}</td>
      <td>{device.online ? 'Online' : 'Offline'}</td>
      <td className="actions">
        {START_MODES.map(({ mode: m, perm, testId, label }) => (
          <Gated key={m} permissions={p} perm={perm} data-testid={testId} onClick={() => start(m)}>{label}</Gated>
        ))}
        <Gated permissions={p} perm="device:file_transfer" data-testid="transfer-files"
          onClick={() => setNotice('File transfer is out of scope — sessions here are records.')}>
          Transfer files
        </Gated>
        {mode === 'rename' ? (
          <form className="inline" onSubmit={rename}>
            <input name="name" defaultValue={device.name} aria-label="New device name" />
            <button type="submit">Save</button>
            <button type="button" onClick={() => setMode(null)}>Cancel</button>
          </form>
        ) : (
          <Gated permissions={p} perm="device:update" data-testid="rename-device" onClick={() => setMode('rename')}>Rename</Gated>
        )}
        {mode === 'confirm-decommission' ? (
          <span className="inline">
            Decommission {device.name}?
            <button type="button" className="danger" onClick={decommission}>Confirm</button>
            <button type="button" onClick={() => setMode(null)}>Cancel</button>
          </span>
        ) : (
          <Gated permissions={p} perm="device:provision" data-testid="decommission-device" onClick={() => setMode('confirm-decommission')}>
            Decommission
          </Gated>
        )}
      </td>
    </tr>
  );
}
