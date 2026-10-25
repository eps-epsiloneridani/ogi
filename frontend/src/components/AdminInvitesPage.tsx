import { useEffect, useState } from "react";
import { Loader2, Trash2, Copy, Check } from "lucide-react";
import { localAuthApi, type Invite } from "../lib/localAuth";
import { Seo } from "./Seo";

/**
 * Admin invite management: mint one-time invite links, hand them to humans
 * offline (no email delivery), and revoke stale ones. Requires an admin
 * session (the backend enforces OGI_ADMIN_EMAILS).
 */
export function AdminInvitesPage() {
  const [invites, setInvites] = useState<Invite[]>([]);
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const load = async () => {
    try {
      setInvites(await localAuthApi.listInvites());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load invites");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await localAuthApi.createInvite(email);
      setEmail("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create invite");
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (token: string) => {
    try {
      await localAuthApi.revokeInvite(token);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke invite");
    }
  };

  const copyLink = async (invite: Invite) => {
    const link = `${window.location.origin}/invite/${invite.token}`;
    await navigator.clipboard.writeText(link);
    setCopied(invite.token);
    setTimeout(() => setCopied(null), 1500);
  };

  return (
    <>
      <Seo title="Invites | OpenGraph Intel" description="Manage account invites." path="/admin/invites" />
      <div className="max-w-2xl mx-auto p-6">
        <h1 className="text-lg font-semibold text-text mb-1">Account invites</h1>
        <p className="text-xs text-text-muted mb-6">
          Mint a one-time invite and hand the link to the person offline. They register a passkey to activate their account.
        </p>

        <form onSubmit={create} className="flex gap-2 mb-6">
          <input
            type="email"
            placeholder="new.user@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="flex-1 px-3 py-2 text-sm bg-bg border border-border rounded text-text focus:outline-none focus:border-accent"
          />
          <button
            type="submit"
            disabled={busy}
            className="px-4 py-2 text-sm bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50"
          >
            {busy && <Loader2 size={14} className="animate-spin inline mr-1" />}
            Create invite
          </button>
        </form>

        {error && <p className="text-xs text-danger mb-4">{error}</p>}

        {loading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 size={20} className="animate-spin text-accent" />
          </div>
        ) : invites.length === 0 ? (
          <p className="text-sm text-text-muted">No invites yet.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {invites.map((invite) => (
              <li
                key={invite.token}
                className="flex items-center justify-between gap-3 p-3 bg-surface border border-border rounded"
              >
                <div className="min-w-0">
                  <p className="text-sm text-text truncate">{invite.email}</p>
                  <p className="text-[11px] text-text-muted">
                    {invite.usedAt ? "used" : `expires ${invite.expiresAt.slice(0, 10)}`}
                  </p>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    onClick={() => copyLink(invite)}
                    title="Copy invite link"
                    className="p-2 text-text-muted hover:text-accent"
                  >
                    {copied === invite.token ? <Check size={14} /> : <Copy size={14} />}
                  </button>
                  <button
                    onClick={() => revoke(invite.token)}
                    title="Revoke"
                    className="p-2 text-text-muted hover:text-danger"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}
