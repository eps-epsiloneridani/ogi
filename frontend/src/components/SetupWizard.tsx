import { useState } from "react";
import { useNavigate } from "react-router";
import { Loader2, Fingerprint, KeyRound, ShieldCheck, Check } from "lucide-react";
import { useAuthStore } from "../stores/authStore";
import { localAuthApi } from "../lib/localAuth";
import { Seo } from "./Seo";

type Step = "claim" | "password" | "totp" | "passkey" | "done";

/**
 * First-run setup wizard. Replaces the old token-claim-then-passkey flow: the
 * admin claims their account against OGI_SETUP_TOKEN, then (in one flow) sets a
 * password + optional display name, optionally enrolls TOTP, and optionally
 * registers a passkey. The passkey step is only offered when WebAuthn can
 * actually run (RPID configured + https origin) AND the browser is a secure
 * context — over plain-HTTP LAN it is silently absent. Completing the wizard
 * lands in the normal login flows (passkey primary / password+TOTP fallback).
 */
export function SetupWizard() {
  const { authStatus, bootstrap, registerPasskey } = useAuthStore();
  const navigate = useNavigate();

  const [step, setStep] = useState<Step>("claim");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // claim
  const [email, setEmail] = useState("");
  const [setupToken, setSetupToken] = useState("");

  // password + display name
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");

  // TOTP
  const [totpEnroll, setTotpEnroll] = useState<{ secret: string; otpauthUri: string; qrDataUri: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  const passkeyOffered = Boolean(authStatus?.webauthnAvailable) && Boolean(window.isSecureContext);

  const claim = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const err = await bootstrap(email, setupToken);
    setBusy(false);
    if (err) setError(err);
    else setStep("password");
  };

  const submitPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await localAuthApi.passwordSet(password);
      if (displayName.trim()) {
        await localAuthApi.profileUpdate(displayName.trim());
      }
      setBusy(false);
      setStep("totp");
    } catch (err) {
      setBusy(false);
      setError(err instanceof Error ? err.message : "Failed to set password");
    }
  };

  const beginTotp = async () => {
    setBusy(true);
    setError(null);
    try {
      setTotpEnroll(await localAuthApi.totpEnrollBegin());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to begin TOTP enrollment");
    } finally {
      setBusy(false);
    }
  };

  const completeTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await localAuthApi.totpEnrollComplete(totpCode);
      setRecoveryCodes(res.recoveryCodes);
      setTotpEnroll(null);
      setTotpCode("");
      setBusy(false);
    } catch (err) {
      setBusy(false);
      setError(err instanceof Error ? err.message : "Invalid code — try again");
    }
  };

  const finishTotp = () => setStep(passkeyOffered ? "passkey" : "done");

  const skipTotp = () => setStep(passkeyOffered ? "passkey" : "done");

  const enrolPasskey = async () => {
    setBusy(true);
    setError(null);
    const err = await registerPasskey();
    setBusy(false);
    if (err) setError(err);
    else setStep("done");
  };

  const skipPasskey = () => setStep("done");

  const finish = () => navigate("/projects");

  const inputCls =
    "px-3 py-2 text-sm bg-bg border border-border rounded text-text focus:outline-none focus:border-accent";

  return (
    <>
      <Seo title="Setup | OpenGraph Intel" description="First-run setup for OpenGraph Intel." path="/login" />
      <div className="flex items-center justify-center h-screen w-screen bg-bg">
        <div className="w-full max-w-sm p-6 bg-surface border border-border rounded-lg shadow-lg">
          <h1 className="text-lg font-semibold text-text mb-1">Set up OpenGraph Intel</h1>
          <p className="text-xs text-text-muted mb-6">First-run setup — create your administrator account.</p>

          {step === "claim" && (
            <form onSubmit={claim} className="flex flex-col gap-3">
              <p className="text-xs text-text-muted">
                Enter your admin email and the setup token the operator gave you.
              </p>
              <input
                type="email"
                placeholder="Admin email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className={inputCls}
              />
              <input
                type="password"
                placeholder="Setup token"
                value={setupToken}
                onChange={(e) => setSetupToken(e.target.value)}
                required
                className={inputCls}
              />
              <button
                type="submit"
                disabled={busy}
                className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
              >
                {busy && <Loader2 size={14} className="animate-spin" />}
                Continue
              </button>
            </form>
          )}

          {step === "password" && (
            <form onSubmit={submitPassword} className="flex flex-col gap-3">
              <p className="text-xs text-text-muted">
                Your username is your email ({email || "…"}). Set a password and, optionally, a display name.
              </p>
              <input
                type="text"
                placeholder="Display name (optional)"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className={inputCls}
              />
              <input
                type="password"
                placeholder="Password (min 8 chars)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                minLength={8}
                required
                className={inputCls}
              />
              <button
                type="submit"
                disabled={busy}
                className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
              >
                {busy ? <Loader2 size={14} className="animate-spin" /> : <KeyRound size={14} />}
                Set password and continue
              </button>
            </form>
          )}

          {step === "totp" && (
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-text">
                <ShieldCheck size={14} className="text-text-muted" />
                Authenticator (optional)
              </div>

              {recoveryCodes ? (
                <div className="flex flex-col gap-3">
                  <p className="text-xs text-text-muted">
                    Authenticator enrolled. Save these recovery codes — each works once in place of your code.
                  </p>
                  <ul className="grid grid-cols-2 gap-2">
                    {recoveryCodes.map((code) => (
                      <li key={code} className="text-xs text-text font-mono">{code}</li>
                    ))}
                  </ul>
                  <button
                    onClick={finishTotp}
                    disabled={busy}
                    className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
                  >
                    Continue
                  </button>
                </div>
              ) : totpEnroll ? (
                <form onSubmit={completeTotp} className="flex flex-col gap-3">
                  <p className="text-xs text-text-muted">
                    Scan the QR with your authenticator app, then verify one code.
                  </p>
                  <div className="flex items-start gap-4">
                    <img src={totpEnroll.qrDataUri} alt="TOTP provisioning QR" className="w-40 h-40 bg-white rounded p-1" />
                    <div className="flex flex-col gap-1 text-xs">
                      <span className="text-text-muted">Secret</span>
                      <code className="text-text break-all select-all">{totpEnroll.secret}</code>
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
                    Add a second factor to password login. Recommended, but you can skip this.
                  </p>
                  <button
                    onClick={beginTotp}
                    disabled={busy}
                    className="px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
                  >
                    Enroll authenticator
                  </button>
                  <button
                    onClick={skipTotp}
                    disabled={busy}
                    className="text-xs text-text-muted underline text-left"
                  >
                    Skip for now
                  </button>
                </div>
              )}
            </div>
          )}

          {step === "passkey" && (
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-text">
                <Fingerprint size={14} className="text-text-muted" />
                Passkey (recommended)
              </div>
              <p className="text-xs text-text-muted">
                Register a passkey as your primary sign-in. You can skip this and sign in with your
                password + authenticator instead.
              </p>
              <button
                onClick={enrolPasskey}
                disabled={busy}
                className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
              >
                {busy ? <Loader2 size={14} className="animate-spin" /> : <Fingerprint size={14} />}
                Register a passkey
              </button>
              <button
                onClick={skipPasskey}
                disabled={busy}
                className="text-xs text-text-muted underline text-left"
              >
                Skip for now
              </button>
            </div>
          )}

          {step === "done" && (
            <div className="flex flex-col gap-3">
              <p className="text-xs text-text-muted">
                Setup complete. You can sign in with what you enrolled here.
              </p>
              <button
                onClick={finish}
                className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover"
              >
                <Check size={14} />
                Finish setup
              </button>
            </div>
          )}

          {error && <p className="text-xs text-danger mt-3">{error}</p>}
        </div>
      </div>
    </>
  );
}
