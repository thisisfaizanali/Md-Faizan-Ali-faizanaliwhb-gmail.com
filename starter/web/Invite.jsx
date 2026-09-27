import React, { useEffect, useState } from 'react';
import { publicApi } from './api.js';
import { ErrorNote } from './ui.jsx';

// /invite/:token. The token is a credential: it is only ever sent back to the API, and
// index.html sets no-referrer so it cannot leak through a Referer header.
export function Invite({ token, onAccepted }) {
  const [invite, setInvite] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let live = true;
    publicApi('GET', `/invites/${encodeURIComponent(token)}`)
      .then((body) => live && setInvite(body))
      .catch((err) => live && setLoadError(err));
    return () => { live = false; };
  }, [token]);

  async function submit(e) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setError(null);
    try {
      await publicApi('POST', `/invites/${encodeURIComponent(token)}/accept`, {
        name: String(form.get('name') ?? ''),
        password: String(form.get('password') ?? ''),
      });
      onAccepted();
    } catch (err) {
      setError(err);
    }
  }

  // Refused: the server's message and nothing else.
  if (loadError) {
    return (
      <main className="centered">
        <div className="card">
          <p className="error" role="alert" data-testid="invite-error" data-error-code={loadError.code}>
            {loadError.message}
          </p>
        </div>
      </main>
    );
  }
  if (!invite) return <main className="centered"><p>Loading invite…</p></main>;

  return (
    <main className="centered">
      <form className="card login" onSubmit={submit}>
        <h1>Join {invite.orgName}</h1>
        <p>
          You've been invited as <strong data-testid="invite-role">{invite.role}</strong>.
        </p>
        <label>
          Email
          <input readOnly value={invite.email} data-testid="invite-email" />
        </label>
        <label>
          Your name
          <input name="name" autoComplete="name" data-testid="invite-name" />
        </label>
        <label>
          Password (at least 8 characters; your existing one if you already have an account)
          <input name="password" type="password" autoComplete="new-password" data-testid="invite-password" />
        </label>
        <button type="submit" data-testid="invite-submit">Accept invite</button>
        <ErrorNote error={error} testId="invite-accept-error" />
      </form>
    </main>
  );
}
