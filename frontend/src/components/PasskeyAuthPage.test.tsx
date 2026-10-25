import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router";

import { PasskeyAuthPage } from "./PasskeyAuthPage";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const defaultAuthStatus = {
  authMode: "local" as const,
  localAuthEnabled: true,
  passwordAuthEnabled: false,
  rpid: "osi.61cygni.co.uk",
  origins: ["https://osi.61cygni.co.uk"],
  webauthnAvailable: false,
  bootstrapRequired: true,
  setupTokenConfigured: true,
};

const authState = {
  authStatus: { ...defaultAuthStatus },
  authMode: "local",
  bootstrap: vi.fn<(email: string, setupToken: string) => Promise<string | null>>(
    async () => null,
  ),
  registerPasskey: vi.fn<() => Promise<string | null>>(async () => null),
  signInWithPasskey: vi.fn<() => Promise<string | null>>(async () => null),
  signInWithPassword: vi.fn<(email: string, password: string) => Promise<string | null>>(
    async () => null,
  ),
};

vi.mock("../stores/authStore", () => ({
  useAuthStore: () => authState,
}));

vi.mock("../lib/localAuth", () => ({
  localAuthApi: {
    passwordSet: vi.fn(async () => ({ ok: true })),
    profileUpdate: vi.fn(async (displayName: string) => ({
      id: "u1",
      email: "rich@multijoy.co.uk",
      displayName,
      avatarUrl: "",
    })),
    totpEnrollBegin: vi.fn(async () => ({
      secret: "ABCDEFGH",
      otpauthUri: "otpauth://totp/x",
      qrDataUri: "data:image/svg+xml;base64,AA",
    })),
    totpEnrollComplete: vi.fn(async () => ({ recoveryCodes: ["AAAA-BBBB"] })),
  },
}));

function getByType(c: HTMLElement, type: string): HTMLInputElement {
  const el = c.querySelector<HTMLInputElement>(`input[type=${type}]`);
  if (!el) throw new Error(`input[type=${type}] not found`);
  return el;
}

async function setInputValue(input: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  await act(async () => {
    setter?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
}

let container: HTMLDivElement | null = null;
let root: Root | null = null;

function render() {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  act(() => {
    root!.render(
      <MemoryRouter initialEntries={["/login"]}>
        <Routes>
          <Route path="/login" element={<PasskeyAuthPage />} />
          <Route path="/projects" element={<div>PROJECTS</div>} />
        </Routes>
      </MemoryRouter>,
    );
  });
  return container;
}

async function clickButton(label: string) {
  const btn = Array.from(document.querySelectorAll("button")).find(
    (b) => b.textContent && b.textContent.includes(label),
  );
  if (!btn) throw new Error(`button not found: ${label}`);
  await act(async () => {
    btn.click();
  });
}

describe("PasskeyAuthPage first-run setup wizard", () => {
  afterEach(() => {
    act(() => root?.unmount());
    container?.remove();
    container = null;
    root = null;
    vi.clearAllMocks();
    authState.authStatus = { ...defaultAuthStatus };
    Object.defineProperty(window, "isSecureContext", { value: false, configurable: true });
  });

  it("after a successful claim, chains into credential enrolment before entering the app", async () => {
    const c = render();
    const email = getByType(c, "email");
    const token = getByType(c, "password");
    await setInputValue(email, "rich@multijoy.co.uk");
    await setInputValue(token, "setup-token-value");
    await clickButton("Continue");
    expect(authState.bootstrap).toHaveBeenCalledWith(
      "rich@multijoy.co.uk",
      "setup-token-value",
    );
    // THE INVARIANT UNDER TEST: a credential-enrolment step (password) must
    // appear, and the app must NOT have been entered yet (the account exists but
    // has no usable credential).
    expect(document.body.textContent).toContain("Set password and continue");
    expect(document.body.textContent).not.toContain("PROJECTS");
  });

  it("completing the wizard (password + skips) enters the workspace", async () => {
    const c = render();
    await setInputValue(getByType(c, "email"), "rich@multijoy.co.uk");
    await setInputValue(getByType(c, "password"), "setup-token-value");
    await clickButton("Continue");

    await setInputValue(getByType(c, "password"), "correct-horse");
    await clickButton("Set password and continue");

    // optional TOTP step — skip (passkey not offered in the non-secure context)
    await clickButton("Skip for now");

    // done step
    await clickButton("Finish setup");
    expect(document.body.textContent).toContain("PROJECTS");
  });

  it("offers the passkey step only when WebAuthn is available AND the browser is a secure context", async () => {
    authState.authStatus = { ...defaultAuthStatus, webauthnAvailable: true };
    Object.defineProperty(window, "isSecureContext", { value: true, configurable: true });

    const c = render();
    await setInputValue(getByType(c, "email"), "rich@multijoy.co.uk");
    await setInputValue(getByType(c, "password"), "setup-token-value");
    await clickButton("Continue");

    await setInputValue(getByType(c, "password"), "correct-horse");
    await clickButton("Set password and continue");

    // skip TOTP → should land on the passkey step (offered), not the done step
    await clickButton("Skip for now");
    expect(document.body.textContent).toContain("Register a passkey");
    expect(document.body.textContent).not.toContain("PROJECTS");
  });
});
