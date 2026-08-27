"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { BlendSignLogo } from "@/components/BlendSignLogo";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const response = await fetch("/api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const data = await response.json();
    if (!response.ok) setError(data.error || "Unable to request a reset link.");
    else setMessage(data.message);
    setBusy(false);
  }

  return (
    <main className="login-page login-page--single">
      <section className="login-panel">
        <form className="login-card" onSubmit={submit}>
          <BlendSignLogo className="login-card-logo" />
          <div><p className="eyebrow">Account recovery</p><h2>Forgot your password?</h2><p>Enter your account email. We will send a secure reset link that expires in 30 minutes.</p></div>
          <label className="field-label">Email address<input className="field-input" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
          {error && <div className="form-error">{error}</div>}
          {message && <div className="form-success">{message}</div>}
          <button className="button button--accent button--full" disabled={busy}>{busy ? "Sending…" : "Send reset link"}</button>
          <Link className="auth-link" href="/login">Back to sign in</Link>
        </form>
      </section>
    </main>
  );
}

