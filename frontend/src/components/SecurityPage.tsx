import { useEffect, useState } from "react";
import { Loader2, KeyRound, ShieldCheck, Copy, Check, Fingerprint } from "lucide-react";
import { useAuthStore } from "../stores/authStore";
import {
  localAuthApi,
  performPasskeyRegistration,
  type TotpStatus,
  type PasskeyCredential,
} from "../lib/localAuth";
import { Seo } from "./Seo";

/**
 * Account security: set a password, enroll/remove the TOTP second factor,
 * view/regenerate one-time recovery codes, and add a passkey — all for the
 * currently logged-in user (the backend enforces the session). Passwords are
 * the LAN fallback when a secure context for passkeys isn't available.
 */
export function SecurityPage() {
  const user = useAuthStore((state) => state.user);

  const [status, setStatus] = useState<TotpStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // password
  const [password, setPassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [passwordMsg, setPasswordMsg] = useState<string | null>(null);

  // passkeys
  const [passkeys, setPasskeys] = useState<PasskeyCredential[]>([]);
  const [passkeyMsg, setPasskeyMsg] = useState<string | null>(null);

  // TOTP enrollment
  const [enroll, setEnroll] = useState<{ secret: string; otpauthUri: string; qrDataUri: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");

  // recovery codes (shown once)
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copied, setCopied] = useState(false);

  // confirmation password for destructive actions
  const [confirmPassword, setConfirmPassword] = useState("");

  const load = async () => {
    try {
      setStatus(await localAuthApi.totpStatus());
      setPasskeys(await localAuthApi.listPasskeys());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load security status");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleSetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setPasswordMsg(null);
    setError(null);
    try {
      await localAuthApi.passwordSet(password, status?.hasPassword ? currentPassword : undefined);
      setPassword("");
      setCurrentPassword("");
      setPasswordMsg("Password updated.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to set password");
    } finally {
      setBusy(false);
    }
  };

  const removePasskey = async (credentialId: string) => {
    setBusy(true);
    setError(null);
    setPasskeyMsg(null);
    try {
      await localAuthApi.removePasskey(credentialId);
      setPasskeyMsg("Passkey removed.");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove passkey");
    } finally {
      setBusy(false);
    }
  };

  const beginEnroll = async () => {
    setBusy(true);
    setError(null);
    try {
      setEnroll(await localAuthApi.totpEnrollBegin());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to begin enrollment");
    } finally {
      setBusy(false);
    }
  };

  const completeEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await localAuthApi.totpEnrollComplete(totpCode);
      setRecoveryCodes(res.recoveryCodes);
      setEnroll(null);
      setTotpCode("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid code — try again");
    } finally {
      setBusy(false);
    }
  };

  const removeTotp = async () => {
    setBusy(true);
    setError(null);
    try {
      await localAuthApi.totpRemove(confirmPassword || undefined);
      setConfirmPassword("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove TOTP");
    } finally {
      setBusy(false);
    }
  };

  const regenerate = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await localAuthApi.recoveryRegenerate(confirmPassword || undefined);
      setRecoveryCodes(res.recoveryCodes);
      setConfirmPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to regenerate codes");
    } finally {
      setBusy(false);
    }
  };

  const addPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      await performPasskeyRegistration();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Passkey registration failed");
    } finally {
      setBusy(false);
    }
  };

  const copyCodes = async () => {
    if (!recoveryCodes) return;
    await navigator.clipboard.writeText(recoveryCodes.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const inputCls =
    "px-3 py-2 text-sm bg-bg border border-border rounded text-text focus:outline-none focus:border-accent";

  return (
    <>
      <Seo title="Security | OpenGraph Intel" description="Manage your account security." path="/security" />
      <div className="max-w-2xl mx-auto p-6">
        <h1 className="text-lg font-semibold text-text mb-1">Account security</h1>
        <p className="text-xs text-text-muted mb-6">
          Signed in as <span className="text-text">{user?.email ?? "…"}</span>. Password + authenticator
          gives you a fallback when passkeys aren't available (e.g. plain-HTTP LAN).
        </p>

        {error && <p className="text-xs text-danger mb-4">{error}</p>}

        {loading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 size={20} className="animate-spin text-accent" />
          </div>
        ) : (
          <div className="flex flex-col gap-6">
            {/* ---- Password ---- */}
            <section className="p-4 bg-surface border border-border rounded">
              <div className="flex items-center gap-2 mb-2">
                <KeyRound size={14} className="text-text-muted" />
                <h2 className="text-sm font-semibold text-text">Password</h2>
              </div>
              <p className="text-xs text-text-muted mb-3">
                {status?.hasPassword
                  ? "A password is set. Change it below."
                  : "No password set. Add one to enable email + password login."}
              </p>
              <form onSubmit={handleSetPassword} className="flex flex-col gap-2">
                {status?.hasPassword && (
                  <input
                    type="password"
                    placeholder="Current password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    required
                    className={inputCls}
                  />
                )}
                <div className="flex gap-2">
                  <input
                    type="password"
                    placeholder="New password (min 8 chars)"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    minLength={8}
                    required
                    className={`${inputCls} flex-1`}
                  />
                  <button
                    type="submit"
                    disabled={busy}
                    className="px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
                  >
                    {status?.hasPassword ? "Update" : "Set"}
                  </button>
                </div>
              </form>
              {passwordMsg && <p className="text-xs text-text-muted mt-2">{passwordMsg}</p>}
            </section>

            {/* ---- TOTP ---- */}
            <section className="p-4 bg-surface border border-border rounded">
              <div className="flex items-center gap-2 mb-2">
                <ShieldCheck size={14} className="text-text-muted" />
                <h2 className="text-sm font-semibold text-text">Authenticator (TOTP)</h2>
              </div>

              {status?.totpEnrolled ? (
                <div className="flex flex-col gap-3">
                  <p className="text-xs text-text-muted">
                    Two-factor authentication is enabled. You'll need your authenticator code (or a
                    recovery code) after your password.
                  </p>
                  <p className="text-xs text-text">
                    {status.recoveryCodesRemaining} recovery code(s) remaining.
                  </p>
                  <div className="flex flex-col gap-2">
                    <input
                      type="password"
                      placeholder="Confirm with your password to make changes"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className={inputCls}
                    />
                    <div className="flex gap-2">
                      <button
                        onClick={regenerate}
                        disabled={busy}
                        className="px-3 py-2 text-xs border border-border text-text rounded hover:bg-surface disabled:opacity-50"
                      >
                        Regenerate recovery codes
                      </button>
                      <button
                        onClick={removeTotp}
                        disabled={busy}
                        className="px-3 py-2 text-xs border border-danger text-danger rounded hover:bg-surface disabled:opacity-50"
                      >
                        Remove authenticator
                      </button>
                    </div>
                  </div>
                </div>
              ) : enroll ? (
                <form onSubmit={completeEnroll} className="flex flex-col gap-3">
                  <p className="text-xs text-text-muted">
                    Scan the QR with your authenticator app, or enter the secret manually, then verify
                    a code.
                  </p>
                  <div className="flex items-start gap-4">
                    <img src={enroll.qrDataUri} alt="TOTP provisioning QR" className="w-40 h-40 bg-white rounded p-1" />
                    <div className="flex flex-col gap-1 text-xs">
                      <span className="text-text-muted">Secret</span>
                      <code className="text-text break-all select-all">{enroll.secret}</code>
                      <span className="text-text-muted mt-2">Issuer</span>
                      <span className="text-text">OpenGraph Intel</span>
                    </div>
                  </div>
                  <input
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="6-digit code"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    required
                    className={inputCls}
                  />
                  <button
                    type="submit"
                    disabled={busy}
                    className="px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
                  >
                    Verify and enable
                  </button>
                </form>
              ) : (
                <div className="flex flex-col gap-3">
                  <p className="text-xs text-text-muted">
                    Enroll an authenticator app to add a second factor to password login.
                  </p>
                  <button
                    onClick={beginEnroll}
                    disabled={busy}
                    className="px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50 self-start"
                  >
                    Enroll authenticator
                  </button>
                </div>
              )}
            </section>

            {/* ---- Recovery codes (shown once) ---- */}
            {recoveryCodes && (
              <section className="p-4 bg-surface border border-border rounded">
                <div className="flex items-center gap-2 mb-2">
                  <h2 className="text-sm font-semibold text-text">Recovery codes</h2>
                  <button onClick={copyCodes} title="Copy" className="p-1 text-text-muted hover:text-accent">
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                  </button>
                </div>
                <p className="text-xs text-text-muted mb-3">
                  Save these now — each can be used once in place of your authenticator code, and they
                  won't be shown again.
                </p>
                <ul className="grid grid-cols-2 gap-2">
                  {recoveryCodes.map((code) => (
                    <li key={code} className="text-xs text-text font-mono">{code}</li>
                  ))}
                </ul>
              </section>
            )}

            {/* ---- Passkey ---- */}
            <section className="p-4 bg-surface border border-border rounded">
              <div className="flex items-center gap-2 mb-2">
                <Fingerprint size={14} className="text-text-muted" />
                <h2 className="text-sm font-semibold text-text">Passkeys</h2>
              </div>
              <p className="text-xs text-text-muted mb-3">
                Add a passkey to this account (requires a secure context: HTTPS or localhost).
                Removing your last passkey is refused if you have no password, so the account
                can never be left with no way to sign in.
              </p>

              {passkeys.length > 0 && (
                <ul className="flex flex-col gap-2 mb-3">
                  {passkeys.map((pk) => (
                    <li key={pk.credentialId} className="flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <p className="text-xs text-text font-mono truncate">{pk.credentialId.slice(0, 24)}…</p>
                        <p className="text-[11px] text-text-muted">
                          {pk.createdAt ? `Added ${new Date(pk.createdAt).toLocaleDateString()}` : "Added"}
                          {pk.transports.length > 0 ? ` · ${pk.transports.join(", ")}` : ""}
                        </p>
                      </div>
                      <button
                        onClick={() => removePasskey(pk.credentialId)}
                        disabled={busy}
                        className="px-3 py-1.5 text-xs border border-danger text-danger rounded hover:bg-surface disabled:opacity-50"
                      >
                        Remove
                      </button>
                    </li>
                  ))}
                </ul>
              )}

              <button
                onClick={addPasskey}
                disabled={busy}
                className="px-4 py-2 text-sm border border-border text-text rounded hover:bg-surface disabled:opacity-50"
              >
                {busy ? <Loader2 size={14} className="animate-spin inline mr-1" /> : <Fingerprint size={14} className="inline mr-1" />}
                Add passkey
              </button>
              {passkeyMsg && <p className="text-xs text-text-muted mt-2">{passkeyMsg}</p>}
            </section>
          </div>
        )}
      </div>
    </>
  );
}
