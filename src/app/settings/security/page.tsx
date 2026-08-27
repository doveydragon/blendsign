"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Icon } from "@/components/Icon";

type Status = { enabled: boolean; recoveryCodesRemaining: number };
type Setup = { secret: string; qrCode: string };

export default function SecurityPage() {
  const router = useRouter();
  const [status, setStatus] = useState<Status | null>(null);
  const [setup, setSetup] = useState<Setup | null>(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetch("/api/settings/security/two-factor").then(async (response) => {
      if (response.status === 401) return router.replace("/login");
      if (response.ok) setStatus(await response.json());
    });
  }, [router]);

  async function beginSetup() {
    setBusy(true); setError(""); setMessage("");
    const response = await fetch("/api/settings/security/two-factor", { method: "POST" });
    const data = await response.json();
    if (response.ok) setSetup(data); else setError(data.error || "Unable to start setup.");
    setBusy(false);
  }

  async function enable(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError("");
    const response = await fetch("/api/settings/security/two-factor", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) });
    const data = await response.json();
    if (response.ok) { setRecoveryCodes(data.recoveryCodes); setSetup(null); setStatus({ enabled: true, recoveryCodesRemaining: data.recoveryCodes.length }); setCode(""); }
    else setError(data.error || "Unable to enable two-factor authentication.");
    setBusy(false);
  }

  async function regenerateCodes() {
    setBusy(true); setError(""); setMessage("");
    const response = await fetch("/api/settings/security/two-factor", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) });
    const data = await response.json();
    if (response.ok) { setRecoveryCodes(data.recoveryCodes); setStatus((current) => current ? { ...current, recoveryCodesRemaining: data.recoveryCodes.length } : current); setCode(""); }
    else setError(data.error || "Unable to generate new recovery codes.");
    setBusy(false);
  }

  async function disableTwoFactor() {
    if (!window.confirm("Disable two-factor authentication for your account?")) return;
    setBusy(true); setError("");
    const response = await fetch("/api/settings/security/two-factor", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) });
    const data = await response.json();
    if (response.ok) { await fetch("/api/auth/logout", { method: "POST" }); router.replace("/login"); router.refresh(); }
    else setError(data.error || "Unable to disable two-factor authentication.");
    setBusy(false);
  }

  if (!status) return <div className="settings-loading">Loading security settings…</div>;

  return (
    <section className="settings-page">
      <header className="settings-page-header"><div><p className="eyebrow">Personal settings</p><h2>Password and security</h2><p>Protect your BlendSign account and legal documents.</p></div><span className="settings-header-icon"><Icon name="shield" size={27} /></span></header>

      <div className="panel security-panel">
        <div className="security-heading"><div><h3>Authenticator app</h3><p>Require a six-digit code after your password at every sign-in.</p></div><span className={`security-status ${status.enabled ? "is-enabled" : ""}`}>{status.enabled ? "Enabled" : "Not enabled"}</span></div>

        {!status.enabled && !setup && !recoveryCodes.length && <button className="button button--accent" onClick={beginSetup} disabled={busy}>{busy ? "Starting…" : "Set up two-factor authentication"}</button>}

        {setup && (
          <form className="two-factor-setup" onSubmit={enable}>
            <div><h3>1. Scan this QR code</h3><p>Open Microsoft Authenticator, Google Authenticator, 1Password or another TOTP app and add a new account.</p></div>
            <img className="two-factor-qr" src={setup.qrCode} alt="BlendSign authenticator QR code" />
            <details><summary>Cannot scan it?</summary><p>Enter this setup key manually:</p><code className="two-factor-secret">{setup.secret}</code></details>
            <label className="field-label">2. Enter the six-digit code<input className="field-input auth-code-input" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} required /></label>
            <div className="form-actions"><button className="button button--accent" disabled={busy}>{busy ? "Checking…" : "Verify and enable"}</button><button className="button button--secondary" type="button" onClick={() => { setSetup(null); setCode(""); }}>Cancel</button></div>
          </form>
        )}

        {status.enabled && !recoveryCodes.length && (
          <div className="security-actions">
            <p>You have {status.recoveryCodesRemaining} unused recovery code{status.recoveryCodesRemaining === 1 ? "" : "s"}.</p>
            <label className="field-label">Current authenticator code<input className="field-input auth-code-input" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} /></label>
            <div className="form-actions"><button className="button button--secondary" type="button" onClick={regenerateCodes} disabled={busy || !code}>Replace recovery codes</button><button className="button button--danger" type="button" onClick={disableTwoFactor} disabled={busy || !code}>Disable two-factor authentication</button></div>
          </div>
        )}

        {recoveryCodes.length > 0 && (
          <div className="recovery-codes">
            <h3>Save your recovery codes now</h3>
            <p>Each code works once if you lose your authenticator. They will not be shown again.</p>
            <div className="recovery-code-grid">{recoveryCodes.map((recoveryCode) => <code key={recoveryCode}>{recoveryCode}</code>)}</div>
            <div className="form-actions"><button className="button button--secondary" type="button" onClick={() => navigator.clipboard.writeText(recoveryCodes.join("\n"))}>Copy codes</button><button className="button button--accent" type="button" onClick={() => { window.location.href = "/login"; }}>I have saved these codes</button></div>
          </div>
        )}

        {error && <div className="form-error">{error}</div>}
        {message && <div className="form-success">{message}</div>}
      </div>

      <div className="panel security-panel"><h3>Password recovery</h3><p>If you forget your password, BlendSign sends a single-use reset link to <strong>{"your account email"}</strong>. The link expires after 30 minutes, and changing the password signs out all existing sessions.</p></div>
    </section>
  );
}
