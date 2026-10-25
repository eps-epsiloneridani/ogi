import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { Loader2, Fingerprint } from "lucide-react";
import { useAuthStore } from "../stores/authStore";
import { localAuthApi } from "../lib/localAuth";
import { Seo } from "./Seo";

/**
 * Accept an admin-minted invite by registering a passkey. The invite link is
 * handed to the human offline (no email delivery), so this page only needs the
 * token from the URL.
 */
export function InviteAcceptPage() {
  const { token } = useParams<{ token: string }>();
  const { registerPasskey } = useAuthStore();
  const navigate = useNavigate();

  const [email, setEmail] = useState<string | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error" | "busy">("loading");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setState("error");
      setError("Missing invite token");
      return;
    }
    localAuthApi
      .peekInvite(token)
      .then((invite) => {
        if (invite.used) {
          setState("error");
          setError("This invite has already been used.");
        } else if (invite.expired) {
          setState("error");
          setError("This invite has expired.");
        } else {
          setEmail(invite.email);
          setState("ready");
        }
      })
      .catch((e) => {
        setState("error");
        setError(e instanceof Error ? e.message : "Invalid invite");
      });
  }, [token]);

  const handleRegister = async () => {
    if (!token) return;
    setState("busy");
    setError(null);
    const err = await registerPasskey(token);
    if (err) {
      setState("ready");
      setError(err);
    } else {
      navigate("/projects");
    }
  };

  return (
    <>
      <Seo title="Accept Invite | OpenGraph Intel" description="Create your passkey to accept the invite." path={`/invite/${token}`} />
      <div className="flex items-center justify-center h-screen w-screen bg-bg">
        <div className="w-full max-w-sm p-6 bg-surface border border-border rounded-lg shadow-lg">
          <h1 className="text-lg font-semibold text-text mb-1">OpenGraph Intel</h1>
          <p className="text-xs text-text-muted mb-6">Accept your invite</p>

          {state === "loading" && (
            <div className="flex items-center justify-center py-8">
              <Loader2 size={20} className="animate-spin text-accent" />
            </div>
          )}

          {state === "error" && <p className="text-sm text-danger">{error}</p>}

          {(state === "ready" || state === "busy") && (
            <div className="flex flex-col gap-3">
              <p className="text-sm text-text">
                Create a passkey for <span className="font-semibold">{email}</span> to finish
                setting up your account.
              </p>
              <button
                onClick={handleRegister}
                disabled={state === "busy"}
                className="flex items-center justify-center gap-2 px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
              >
                {state === "busy" ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <Fingerprint size={14} />
                )}
                Create passkey
              </button>
              {error && <p className="text-xs text-danger">{error}</p>}
              <p className="text-[11px] text-text-muted text-center">
                Passkeys require a secure context — use this site over HTTPS or on localhost.
              </p>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
