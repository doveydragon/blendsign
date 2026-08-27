"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Icon } from "@/components/Icon";
import { BlendSignLogo } from "@/components/BlendSignLogo";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [challengeToken, setChallengeToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const response = challengeToken
      ? await fetch("/api/auth/two-factor", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ challengeToken, code }) })
      : await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
    const data = await response.json();
    if (!response.ok) {
      setError(data.error || "Unable to sign in.");
      setBusy(false);
      return;
    }
    if (data.requiresTwoFactor) {
      setChallengeToken(data.challengeToken);
      setPassword("");
      setBusy(false);
      return;
    }
    router.push("/dashboard");
    router.refresh();
  }

  return (
    <main className="login-page">
      <section className="login-brand">
        <BlendSignLogo inverse className="login-brand-logo" />
        <p className="eyebrow">Blend Property Group</p>
        <h1>Secure agreements.<br />One stable.</h1>
        <p>Manage every signing workflow across Blend Property Group, Stor 24 and future operating companies.</p>
        <div className="login-assurance"><Icon name="shield" size={20} /><span>Private company workspaces<br /><small>South African-hosted document storage</small></span></div>
      </section>
      <section className="login-panel">
        <form className="login-card" onSubmit={submit}>
          <BlendSignLogo className="login-card-logo" />
          <div><p className="eyebrow">Administration</p><h2>{challengeToken ? "Two-factor authentication" : "Sign in to BlendSign"}</h2><p>{challengeToken ? "Enter the six-digit code from your authenticator app, or use one recovery code." : "Use your administrator or company user credentials."}</p></div>
          {challengeToken ? (
            <label className="field-label">Authentication code<input className="field-input auth-code-input" type="text" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} required autoFocus /></label>
          ) : (
            <>
              <label className="field-label">Email address<input className="field-input" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
              <label className="field-label">Password<input className="field-input" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
              <Link className="auth-link auth-link--right" href="/forgot-password">Forgot password?</Link>
            </>
          )}
          {error && <div className="form-error">{error}</div>}
          <button className="button button--accent button--full" disabled={busy}>{busy ? "Checking…" : challengeToken ? "Verify and sign in" : "Sign in"}</button>
          {challengeToken && <button className="auth-link auth-link--button" type="button" onClick={() => { setChallengeToken(""); setCode(""); setError(""); }}>Use a different account</button>}
        </form>
      </section>
    </main>
  );
}
