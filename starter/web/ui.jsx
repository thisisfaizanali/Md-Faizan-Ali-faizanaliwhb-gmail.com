import React, { useCallback, useEffect, useState } from 'react';

// Presence, not state: a gated element exists only when the SERVER's resolved set says
// allow. There is no disabled variant, and no permission logic here beyond reading it.
export const allowed = (permissions, key) => permissions?.[key]?.effect === 'allow';

export function Gated({ permissions, perm, as: Tag = 'button', children, ...rest }) {
  if (!allowed(permissions, perm)) return null;
  const extra = Tag === 'button' ? { type: 'button' } : {};
  return (
    <Tag {...extra} {...rest} data-permission={perm} data-state="unlocked">
      {children}
    </Tag>
  );
}

// Every failure is shown in the server's own words. Forms use this inline; failures
// outside a form go to the shell's single request-error banner.
export function ErrorNote({ error, testId }) {
  if (!error) return null;
  return (
    <p className="error" role="alert" data-testid={testId} data-error-code={error.code}>
      {error.message}
      {error.reason && <span className="reason"> ({error.reason})</span>}
    </p>
  );
}

export function Notice({ children }) {
  if (!children) return null;
  return <p className="notice" role="status">{children}</p>;
}

// Fetch on mount (and whenever `load` changes); failures go to `report`. Returns the data
// and a reload function. `load` must be memoised by the caller.
export function useResource(load, report) {
  const [data, setData] = useState(null);
  const reload = useCallback(() => {
    let live = true;
    load()
      .then((d) => live && setData(d))
      .catch((err) => live && report(err));
    return () => { live = false; };
  }, [load, report]);
  useEffect(reload, [reload]);
  return [data, reload];
}

// Run a mutation; on failure hand the error to `onError` instead of throwing.
// Resolves to { ok, value } so a successful empty response (204) is not mistaken for failure.
export async function attempt(action, onError) {
  try {
    return { ok: true, value: await action() };
  } catch (err) {
    onError(err);
    return { ok: false };
  }
}

export const formValue = (form, name) => String(new FormData(form).get(name) ?? '').trim();

export const when = (iso) => (iso ? new Date(iso).toLocaleString() : '—');
