import { useState } from "react";
import { useNavigate } from "react-router";
import { Loader2, Fingerprint, KeyRound } from "lucide-react";
import { useAuthStore } from "../stores/authStore";
import { Seo } from "./Seo";
import { SetupWizard } from "./SetupWizard";

/**
 * Local (passkey-first) auth screen. Replaces the Supabase AuthPage when
 * VITE_LOCAL_AUTH_ENABLED is set. Primary path is a WebAuthn passkey; an
 * optional argon2 password fallback appears only when the backend enables it.
 * On a fresh install it renders the first-run setup wizard (token-gated admin
 * enrolment), which owns the whole claim → credential → optional TOTP →
 * optional passkey flow.
 */
export function PasskeyAuthPage() {
  const { authStatus, signInWithPasskey, signInWithPassword } = useAuthStore();
  const navigate = useNavigate();

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");

  const bootstrapRequired = authStatus?.bootstrapRequired ?? false;
  const passwordAuthEnabled = authStatus?.passwordAuthEnabled ?? false;
  const totpRequired = authStatus?.totpRequired ?? false;

  const run = async (fn: () => Promise<string | null>) => {
    setBusy(true);
    setError(null);
    const err = await fn();
    setBusy(false);
    if (err) setError(err);
    else navigate("/projects");
  };

  const handlePasskey = () => run(signInWithPasskey);

  const handlePassword = (e: React.FormEvent) => {
    e.preventDefault();
    const code = totpCode.trim();
    // A recovery code (XXXX-XXXX) and a 6-digit TOTP are both accepted in the
    // same field; route to the right backend parameter.
    const isRecovery = code.length > 6 || code.includes("-");
    run(() =>
      signInWithPassword(email, password, isRecovery ? undefined : code || undefined, isRecovery ? code : undefined),
    );
  };

  if (bootstrapRequired) {
    return <SetupWizard />;
  }

  return (
    <>
      <Seo title="Sign In | OpenGraph Intel" description="Sign in to OpenGraph Intel with your passkey." path="/login" />
      <div className="flex items-center justify-center h-screen w-screen bg-bg">
        <div className="w-full max-w-sm p-6 bg-surface border border-border rounded-lg shadow-lg">
          <h1 className="text-lg font-semibold text-text mb-1">OpenGraph Intel</h1>
          <p className="text-xs text-text-muted mb-6">Sign in to continue</p>

          <div className="flex flex-col gap-3">
            <button
              onClick={handlePasskey}
              disabled={busy}
              className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover disabled:opacity-50"
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
                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder={totpRequired ? "Authenticator code" : "Authenticator / recovery code (if enrolled)"}
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
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

          {error && <p className="text-xs text-danger mt-3">{error}</p>}
        </div>
      </div>
    </>
  );
}
