import React, { useCallback, useState } from 'react';
import { api } from '../api.js';
import { useResource, when } from '../ui.jsx';

const PAGE = 50;

export function Audit({ orgId, report }) {
  const [offset, setOffset] = useState(0);
  const load = useCallback(
    () => api('GET', `/orgs/${orgId}/audit?limit=${PAGE}&offset=${offset}`).then((b) => b.events),
    [orgId, offset],
  );
  const [events] = useResource(load, report);

  return (
    <section>
      <header className="view-head">
        <h2>Audit log</h2>
        <div className="inline">
          {offset > 0 && <button type="button" onClick={() => setOffset(Math.max(0, offset - PAGE))}>Newer</button>}
          {events?.length === PAGE && <button type="button" onClick={() => setOffset(offset + PAGE)}>Older</button>}
        </div>
      </header>
      {events?.length === 0 && <p>No events.</p>}
      {events?.length > 0 && (
        <table>
          <thead>
            <tr><th>At</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Reason</th></tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} data-testid="audit-row" data-result={e.result}>
                <td>{when(e.at)}</td>
                <td>{e.actor_id ?? '—'}</td>
                <td>{e.action}</td>
                <td>{e.target_type ? `${e.target_type} ${e.target_id ?? ''}` : '—'}</td>
                <td>{e.result}</td>
                <td>{e.reason_code ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
