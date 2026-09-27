import React from 'react';

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

// Every failure is shown in the server's own words.
export function ErrorNote({ error, testId }) {
  if (!error) return null;
  return (
    <p className="error" role="alert" data-testid={testId} data-error-code={error.code}>
      {error.message}
    </p>
  );
}

export function Notice({ children }) {
  if (!children) return null;
  return <p className="notice" role="status">{children}</p>;
}
