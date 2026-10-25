import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router";

import { PasskeyAuthPage } from "./PasskeyAuthPage";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const authState = {
  authStatus: {
    authMode: "local" as const,
    localAuthEnabled: true,
    passwordAuthEnabled: false,
    rpid: "osi.61cygni.co.uk",
    origins: ["https://osi.61cygni.co.uk"],
    bootstrapRequired: true,
    setupTokenConfigured: true,
  },
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

describe("PasskeyAuthPage first-run bootstrap", () => {
  afterEach(() => {
    act(() => root?.unmount());
    container?.remove();
    container = null;
    root = null;
    vi.clearAllMocks();
  });

  it("after a successful bootstrap, chains into passkey enrolment before entering the app", async () => {
    const c = render();
    const email = getByType(c, "email");
    const token = getByType(c, "password");
    await setInputValue(email, "rich@multijoy.co.uk");
    await setInputValue(token, "setup-token-value");
    const submit = Array.from(c.querySelectorAll("button")).find((b) =>
      (b.textContent || "").includes("Claim admin account"),
    );
    if (!submit) throw new Error("bootstrap submit not found");
    await act(async () => {
      submit.click();
    });
    expect(authState.bootstrap).toHaveBeenCalledWith(
      "rich@multijoy.co.uk",
      "setup-token-value",
    );
    // THE FIX UNDER TEST: an enrolment step must appear, and the app must NOT
    // have been entered yet (the account exists but has no credential).
    expect(document.body.textContent).toContain("Register your passkey");
    expect(document.body.textContent).not.toContain("PROJECTS");
  });

  it("only enters the workspace once the enrolment ceremony succeeds", async () => {
    const c = render();
    const email = getByType(c, "email");
    const token = getByType(c, "password");
    await setInputValue(email, "rich@multijoy.co.uk");
    await setInputValue(token, "setup-token-value");
    await clickButton("Claim admin account");
    await clickButton("Register your passkey");
    expect(authState.registerPasskey).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).toContain("PROJECTS");
  });
});