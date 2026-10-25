import { create } from "zustand";
import { supabase } from "../lib/supabase";
import type { Session } from "@supabase/supabase-js";
import { getEnv } from "../lib/env";
import {
  localAuthApi,
  performPasskeyLogin,
  performPasskeyRegistration,
  type AuthStatus,
  type LocalUser,
} from "../lib/localAuth";

export type AuthMode = "supabase" | "local" | "anonymous";

/** Unified user shape exposed to the UI regardless of auth backend. */
export interface AuthUser {
  id: string;
  email: string;
  user_metadata?: { display_name?: string };
}

const isTruthy = (v: string | undefined) => v === "true" || v === "1";

/** Local (passkey-first) auth is on when the operator sets the flag and no Supabase. */
export const localAuthEnabled = isTruthy(getEnv("VITE_LOCAL_AUTH_ENABLED"));
export const authMode: AuthMode =
  supabase !== null ? "supabase" : localAuthEnabled ? "local" : "anonymous";

function toAuthUser(u: { id: string; email?: string | null; user_metadata?: unknown }): AuthUser {
  const meta = (u.user_metadata ?? {}) as { display_name?: unknown };
  return {
    id: u.id,
    email: u.email ?? "",
    user_metadata: { display_name: typeof meta.display_name === "string" ? meta.display_name : "" },
  };
}

interface AuthState {
  user: AuthUser | null;
  session: Session | null;
  loading: boolean;
  /** true when any auth backend (Supabase or local) is active */
  authEnabled: boolean;
  authMode: AuthMode;
  /** runtime status from the local-auth backend (null unless local mode) */
  authStatus: AuthStatus | null;
  /** true when the user arrived via a Supabase recovery link */
  isRecovery: boolean;

  initialize: () => Promise<void>;
  signIn: (email: string, password: string, captchaToken?: string) => Promise<string | null>;
  signUp: (email: string, password: string, captchaToken?: string) => Promise<string | null>;
  signOut: () => Promise<void>;
  resetPassword: (email: string, captchaToken?: string) => Promise<string | null>;
  updatePassword: (newPassword: string) => Promise<string | null>;
  updateProfile: (displayName: string) => Promise<string | null>;
  clearRecovery: () => void;

  // local (passkey-first) auth
  bootstrap: (email: string, setupToken: string) => Promise<string | null>;
  signInWithPasskey: () => Promise<string | null>;
  registerPasskey: (inviteToken?: string) => Promise<string | null>;
  signInWithPassword: (
    email: string,
    password: string,
    totpCode?: string,
    recoveryCode?: string,
  ) => Promise<string | null>;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  session: null,
  loading: true,
  authEnabled: supabase !== null || localAuthEnabled,
  authMode,
  authStatus: null,
  isRecovery: false,

  initialize: async () => {
    // Supabase path (unchanged)
    if (supabase) {
      const {
        data: { session },
      } = await supabase.auth.getSession();
      set({
        session,
        user: session?.user ? toAuthUser(session.user) : null,
        loading: false,
      });
      supabase.auth.onAuthStateChange((event, session) => {
        set({
          session,
          user: session?.user ? toAuthUser(session.user) : null,
        });
        if (event === "PASSWORD_RECOVERY") set({ isRecovery: true });
      });
      return;
    }

    // Local passkey path: reconcile status + restore cookie session
    if (localAuthEnabled) {
      try {
        const [status, me] = await Promise.allSettled([
          localAuthApi.status(),
          localAuthApi.me(),
        ]);
        const st = status.status === "fulfilled" ? status.value : null;
        const user = me.status === "fulfilled" ? toAuthUser(me.value as never) : null;
        set({ authStatus: st, user, loading: false });
      } catch {
        set({ loading: false });
      }
      return;
    }

    set({ loading: false });
  },

  signIn: async (email, password, captchaToken) => {
    if (!supabase) return "Auth not configured";
    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
      options: captchaToken ? { captchaToken } : undefined,
    });
    return error ? error.message : null;
  },

  signUp: async (email, password, captchaToken) => {
    if (!supabase) return "Auth not configured";
    const redirectUrl = getEnv("VITE_SUPABASE_REDIRECT_URL") || window.location.origin;
    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: { emailRedirectTo: redirectUrl, captchaToken },
    });
    return error ? error.message : null;
  },

  signOut: async () => {
    if (supabase) {
      await supabase.auth.signOut();
    } else if (localAuthEnabled) {
      try {
        await localAuthApi.logout();
      } catch {
        /* ignore network errors on logout */
      }
    }
    set({ user: null, session: null, isRecovery: false });
  },

  resetPassword: async (email, captchaToken) => {
    if (!supabase) return "Auth not configured";
    const redirectUrl = getEnv("VITE_SUPABASE_REDIRECT_URL") || window.location.origin;
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: redirectUrl,
      captchaToken,
    });
    return error ? error.message : null;
  },

  updatePassword: async (newPassword) => {
    if (!supabase) return "Auth not configured";
    const { error } = await supabase.auth.updateUser({ password: newPassword });
    if (error) return error.message;
    set({ isRecovery: false });
    return null;
  },

  updateProfile: async (displayName) => {
    if (!supabase) return "Auth not configured";
    const { data, error } = await supabase.auth.updateUser({
      data: { display_name: displayName },
    });
    if (error) return error.message;
    if (data.user) set({ user: toAuthUser(data.user) });
    return null;
  },

  clearRecovery: () => set({ isRecovery: false }),

  // ---- local auth ----
  bootstrap: async (email, setupToken) => {
    if (authMode !== "local") return "Local auth not configured";
    try {
      const { user } = await localAuthApi.bootstrap(email, setupToken);
      set({ user: toAuthUser(user as never), loading: false });
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : "Bootstrap failed";
    }
  },

  signInWithPasskey: async () => {
    if (authMode !== "local") return "Local auth not configured";
    try {
      const user: LocalUser = await performPasskeyLogin();
      set({ user: toAuthUser(user as never), loading: false });
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : "Passkey login failed";
    }
  },

  registerPasskey: async (inviteToken) => {
    if (authMode !== "local") return "Local auth not configured";
    try {
      const user: LocalUser = await performPasskeyRegistration(inviteToken);
      set({ user: toAuthUser(user as never), loading: false });
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : "Passkey registration failed";
    }
  },

  signInWithPassword: async (email, password, totpCode, recoveryCode) => {
    if (authMode !== "local") return "Local auth not configured";
    try {
      const { user } = await localAuthApi.passwordLogin(email, password, totpCode, recoveryCode);
      set({ user: toAuthUser(user as never), loading: false });
      return null;
    } catch (e) {
      return e instanceof Error ? e.message : "Password login failed";
    }
  },
}));
