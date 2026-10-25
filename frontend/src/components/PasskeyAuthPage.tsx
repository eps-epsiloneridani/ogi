import { useState } from "react";
import { useNavigate } from "react-router";
import { Loader2, Fingerprint, KeyRound } from "lucide-react";
import { useAuthStore } from "../stores/authStore";
import { Seo } from "./Seo";

/**
 * Local (passkey-first) auth screen. Replaces the Supabase AuthPage when
 * VITE_LOCAL_AUTH_ENABLED is set. Primary path is a WebAuthn passkey; an
 * optional argon2 password fallback appears only when the backend enables it.
 * On a fresh install it also exposes the first-admin bootstrap (setup token).
 */
export function PasskeyAuthPage() {
  const { authStatus, bootstrap, registerPasskey, signInWithPasskey, signInWithPassword } = useAuthStore();
  const navigate = useNavigate();

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [setupEmail, setSetupEmail] = useState("");
  const [setupToken, setSetupToken] = useState("");
  const [enrolStage, setEnrolStage] = useState(false);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const bootstrapRequired = authStatus?.bootstrapRequired ?? false;
  const passwordAuthEnabled = authStatus?.passwordAuthEnabled ?? false;

  const run = async (fn: () => Promise<string | null>, onOk?: () => void) => {
    setBusy(true);
    setError(null);
    const err = await fn();
    setBusy(false);
    if (err) setError(err);
    else if (onOk) onOk();
    else navigate("/projects");
  };

  // First-run bootstrap claims the admin account; the WebAuthn ENROLMENT
  // ceremony must chain immediately after it (same page, fresh user gesture for
  // the create() call) — a bootstrapped admin without a passkey cannot sign in
  // to anything. The backend already sets the session cookie on bootstrap, so
  // register/begin accepts the call without an invite token.
  const handleBootstrap = (e: React.FormEvent) => {
    e.preventDefault();
    run(() => bootstrap(setupEmail, setupToken), () => setEnrolStage(true));
  };

  const handleEnrolPasskey = () => run(() => registerPasskey());

  const handlePasskey = () => run(signInWithPasskey);

  const handlePassword = (e: React.FormEvent) => {
    e.preventDefault();
    run(() => signInWithPassword(email, password));
  };

  return (
    <>
      <Seo title="Sign In | OpenGraph Intel" description="Sign in to OpenGraph Intel with your passkey." path="/login" />
      <div className="flex items-center justify-center h-screen w-screen bg-bg">
        <div className="w-full max-w-sm p-6 bg-surface border border-border rounded-lg shadow-lg">
          <h1 className="text-lg font-semibold text-text mb-1">OpenGraph Intel</h1>
          <p className="text-xs text-text-muted mb-6">Sign in to continue</p>

          {enrolStage ? (
            <div className="flex flex-col gap-3">
              <p className="text-xs text-text-muted">
                Admin account claimed. Now register your passkey — this is how you sign
                in from now on.
              </p>
              <button
                onClick={handleEnrolPasskey}
                disabled={busy}
                className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
              >
                {busy ? <Loader2 size={14} className="animate-spin" /> : <Fingerprint size={14} />}
                Register your passkey
              </button>
              <button
                onClick={() => navigate("/projects")}
                disabled={busy}
                className="text-xs text-text-muted underline text-left"
              >
                Skip for now — you will not be able to sign in until a passkey is registered
              </button>
            </div>
          ) : bootstrapRequired ? (
            <form onSubmit={handleBootstrap} className="flex flex-col gap-3">
              <p className="text-xs text-text-muted">
                First-run setup: claim your admin account with the setup token the operator gave you.
              </p>
              <input
                type="email"
                placeholder="Admin email"
                value={setupEmail}
                onChange={(e) => setSetupEmail(e.target.value)}
                required
                className="px-3 py-2 text-sm bg-bg border border-border rounded text-text focus:outline-none focus:border-accent"
              />
              <input
                type="password"
                placeholder="Setup token"
                value={setupToken}
                onChange={(e) => setSetupToken(e.target.value)}
                required
                className="px-3 py-2 text-sm bg-bg border border-border rounded text-text focus:outline-none focus:border-accent"
              />
              <button
                type="submit"
                disabled={busy}
                className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
              >
                {busy && <Loader2 size={14} className="animate-spin" />}
                Claim admin account
              </button>
            </form>
          ) : (
            <div className="flex flex-col gap-3">
              <button
                onClick={handlePasskey}
                disabled={busy}
                className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
              >
                {busy ? <Loader2 size={14} className="animate-spin" /> : <Fingerprint size={14} />}
                Sign in with passkey
              </button>

              {passwordAuthEnabled && (
                <form onSubmit={handlePassword} className="flex flex-col gap-3 mt-2">
                  <div className="flex items-center gap-2 text-xs text-text-muted">
                    <KeyRound size={12} /> or use a password
                  </div>
                  <input
                    type="email"
                    placeholder="Email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="px-3 py-2 text-sm bg-bg border border-border rounded text-text focus:outline-none focus:border-accent"
                  />
                  <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="px-3 py-2 text-sm bg-bg border border-border rounded text-text focus:outline-none focus:border-accent"
                  />
                  <button
                    type="submit"
                    disabled={busy}
                    className="flex items-center justify-center gap-2 px-4 py-2 text-sm border border-border text-text rounded hover:bg-surface disabled:opacity-50"
                  >
                    {busy && <Loader2 size={14} className="animate-spin" />}
                    Sign in with password
                  </button>
                </form>
              )}

              <p className="text-[11px] text-text-muted text-center mt-2">
                Passkeys require a secure context — use this site over HTTPS or on localhost.
              </p>
            </div>
          )}

          {error && <p className="text-xs text-danger mt-3">{error}</p>}
        </div>
      </div>
    </>
  );
}
