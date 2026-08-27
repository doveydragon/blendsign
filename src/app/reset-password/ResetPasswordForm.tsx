"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { BlendSignLogo } from "@/components/BlendSignLogo";

export function ResetPasswordForm({ token }: { token: string }) {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [complete, setComplete] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (password !== confirmPassword) return setError("The passwords do not match.");
    setBusy(true);
    const response = await fetch("/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, password }),
    });
    const data = await response.json();
    if (!response.ok) setError(data.error || "Unable to reset the password.");
    else setComplete(true);
    setBusy(false);
  }

  return (
    <main className="login-page login-page--single">
      <section className="login-panel">
        <form className="login-card" onSubmit={submit}>
          <BlendSignLogo className="login-card-logo" />
          {complete ? (
            <>
              <div><p className="eyebrow">Password changed</p><h2>Your password is ready</h2><p>All existing BlendSign sessions have been signed out. Use your new password to continue.</p></div>
              <Link className="button button--accent button--full" href="/login">Return to sign in</Link>
            </>
          ) : (
            <>
              <div><p className="eyebrow">Account recovery</p><h2>Choose a new password</h2><p>Use at least 12 characters with upper- and lower-case letters, a number and a symbol.</p></div>
              {!token && <div className="form-error">This reset link is incomplete. Request a new one.</div>}
              <label className="field-label">New password<input className="field-input" type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
              <label className="field-label">Confirm new password<input className="field-input" type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required /></label>
              {error && <div className="form-error">{error}</div>}
              <button className="button button--accent button--full" disabled={busy || !token}>{busy ? "Changing…" : "Change password"}</button>
              <Link className="auth-link" href="/forgot-password">Request another link</Link>
            </>
          )}
        </form>
      </section>
    </main>
  );
}

