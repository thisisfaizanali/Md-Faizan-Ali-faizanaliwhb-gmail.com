import React, { useState } from 'react';
import { login } from './api.js';
import { ErrorNote } from './ui.jsx';

function missingFields(email, password) {
  const missing = [!email && 'email', !password && 'password'].filter(Boolean);
  return missing.length ? `Enter your ${missing.join(' and ')}` : null;
}

// The error stays until the next submit, and is never reworded: a wrong password and an
// unknown account must read identically.
export function Login({ initialError = null }) {
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const email = String(form.get('email') ?? '').trim();
    const password = String(form.get('password') ?? '');
    setError(null);

    const missing = missingFields(email, password);
    if (missing) return setError({ code: 'MISSING_FIELDS', message: missing });

    setBusy(true);
    try {
      await login(email, password); // the session subscription swaps in the shell
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  }

  return (
    <main className="centered">
      <form className="card login" data-testid="login-form" onSubmit={submit} noValidate>
        <h1>RemoteOps</h1>
        <label>
          Email
          <input name="email" type="email" autoComplete="username" data-testid="login-email" />
        </label>
        <label>
          Password
          <input name="password" type="password" autoComplete="current-password" data-testid="login-password" />
        </label>
        <button type="submit" data-testid="login-submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        <ErrorNote error={error} testId="login-error" />
      </form>
    </main>
  );
}
