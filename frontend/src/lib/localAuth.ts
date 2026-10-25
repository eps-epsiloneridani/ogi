import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";

/** A user as exposed to the UI in local-auth mode. */
export interface LocalUser {
  id: string;
  email: string;
  displayName: string;
  avatarUrl: string;
}

export interface AuthStatus {
  authMode: "supabase" | "local" | "anonymous";
  localAuthEnabled: boolean;
  passwordAuthEnabled: boolean;
  rpid: string;
  origins: string[];
  bootstrapRequired: boolean;
  setupTokenConfigured: boolean;
}

export interface Invite {
  token: string;
  email: string;
  role: string;
  createdBy: string | null;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "include",
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const data = await res.json();
      if (data?.error?.message) detail = data.error.message;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });
}
function get<T>(path: string): Promise<T> {
  return request<T>(path, { method: "GET" });
}
function del<T>(path: string): Promise<T> {
  return request<T>(path, { method: "DELETE" });
}

export const localAuthApi = {
  status: () => get<AuthStatus>("/api/v1/auth/status"),
  me: () => get<LocalUser>("/api/v1/auth/me"),
  logout: () => post<{ ok: boolean }>("/api/v1/auth/logout"),

  bootstrap: (email: string, setupToken: string) =>
    post<{ user: LocalUser; token: string }>("/api/v1/auth/bootstrap", { email, setupToken }),

  loginBegin: () =>
    post<{ challengeId: string; options: Record<string, unknown> }>(
      "/api/v1/auth/webauthn/login/begin",
    ),
  loginComplete: (challengeId: string, assertion: unknown) =>
    post<{ user: LocalUser; token: string }>("/api/v1/auth/webauthn/login/complete", {
      challengeId,
      assertion,
    }),

  registerBegin: (inviteToken?: string) =>
    post<{ challengeId: string; options: Record<string, unknown>; inviteToken?: string }>(
      "/api/v1/auth/webauthn/register/begin",
      inviteToken ? { inviteToken } : {},
    ),
  registerComplete: (challengeId: string, attestation: unknown, inviteToken?: string) =>
    post<{ user: LocalUser; token: string }>("/api/v1/auth/webauthn/register/complete", {
      challengeId,
      attestation,
      inviteToken,
    }),

  passwordLogin: (email: string, password: string) =>
    post<{ user: LocalUser; token: string }>("/api/v1/auth/password/login", { email, password }),
  passwordSet: (password: string) =>
    post<{ ok: boolean }>("/api/v1/auth/password/set", { password }),

  createInvite: (email: string) => post<Invite>("/api/v1/auth/invites", { email }),
  listInvites: () => get<Invite[]>("/api/v1/auth/invites"),
  revokeInvite: (token: string) => del<undefined>(`/api/v1/auth/invites/${token}`),
  peekInvite: (token: string) =>
    get<{ email: string; used: boolean; expired: boolean }>(`/api/v1/auth/invites/${token}`),
};

/** Convenience wrappers around the WebAuthn ceremony. */
export async function performPasskeyLogin(): Promise<LocalUser> {
  const begin = await localAuthApi.loginBegin();
  const assertion = await startAuthentication({ optionsJSON: begin.options as never });
  const result = await localAuthApi.loginComplete(begin.challengeId, assertion);
  return result.user;
}

export async function performPasskeyRegistration(
  inviteToken?: string,
): Promise<LocalUser> {
  const begin = await localAuthApi.registerBegin(inviteToken);
  const attestation = await startRegistration({ optionsJSON: begin.options as never });
  const result = await localAuthApi.registerComplete(
    begin.challengeId,
    attestation,
    inviteToken,
  );
  return result.user;
}
