import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { refresh, subscribe } from './api.js';
import { Login } from './Login.jsx';
import { Invite } from './Invite.jsx';
import { Shell } from './Shell.jsx';
import './styles.css';

// The console. Everything permission-gated is resolved by the SERVER: this code renders the
// resolved sets it is given and holds no role-to-permission table (UI-INVENTORY.md).

const inviteToken = () => /^\/invite\/([^/]+)$/.exec(window.location.pathname)?.[1] ?? null;

function App() {
  const [invite, setInvite] = useState(inviteToken);
  // 'booting' | 'signed-out' | 'signed-in'
  const [phase, setPhase] = useState(invite ? 'signed-out' : 'booting');
  const [session, setSession] = useState(null);
  const [bootError, setBootError] = useState(null);

  useEffect(() => subscribe((shape) => {
    setSession(shape);
    setPhase('signed-in');
  }), []);

  // Resume from the refresh cookie, once, on first load only: after an invite is accepted
  // the user signs in explicitly. The API module dedupes concurrent refreshes, so
  // StrictMode's double effect cannot replay the cookie.
  useEffect(() => {
    if (inviteToken()) return;
    refresh().catch((err) => {
      if (err.status !== 401) setBootError(err);
      setPhase('signed-out');
    });
  }, []);

  if (invite) {
    // Accepting does not sign in through the cookie: drop the token from the URL and show
    // the sign-in form.
    const accepted = () => {
      window.history.replaceState(null, '', '/');
      setInvite(null);
      setPhase('signed-out');
    };
    return <Invite token={decodeURIComponent(invite)} onAccepted={accepted} />;
  }
  if (phase === 'booting') return <main className="centered"><p>Loading…</p></main>;
  if (phase === 'signed-out' || !session) return <Login initialError={bootError} />;

  const signedOut = () => {
    setSession(null);
    setBootError(null);
    setPhase('signed-out');
  };
  // Keyed on the org: nothing from the previous org survives a switch.
  return <Shell key={session.org.id} session={session} onSignedOut={signedOut} />;
}

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
