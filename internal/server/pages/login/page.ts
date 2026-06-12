import * as opaque from "@serenity-kit/opaque";
import { setAuthCookie } from "../lib/cookie";

const baseUrl = "/api/opaque";

interface OpaqueLoginToken {
    kind: "token";
    token: string;
}

interface OpaqueLogin2FA {
    kind: "2fa";
    sessionId: string;
    methods: string[];
}

type OpaqueLoginResult = OpaqueLoginToken | OpaqueLogin2FA;

function getInput(id: string): HTMLInputElement {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLInputElement)) throw new Error(`element #${id} is not an input`);
    return el;
}

async function opaqueLogin(clientId: string, password: string): Promise<OpaqueLoginResult> {
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
        password,
    });

    const res1 = await fetch(`${baseUrl}/login/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: startLoginRequest }),
    });
    if (!res1.ok) throw new Error(await res1.text());
    const loginResponse = await res1.text();

    const result = opaque.client.finishLogin({
        clientLoginState,
        password,
        loginResponse,
    });
    if (!result) throw new Error("login failed");

    const { finishLoginRequest } = result;
    const res2 = await fetch(`${baseUrl}/login/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: finishLoginRequest }),
    });
    if (!res2.ok) throw new Error(await res2.text());

    const data = await res2.json();
    if (data.token) return { kind: "token", token: data.token };
    if (data.status === "2fa_required") {
        return {
            kind: "2fa",
            sessionId: data.session_id,
            methods: data.methods,
        };
    }
    throw new Error("unexpected response");
}

async function init() {
    await opaque.ready;

    function registerHandlers() {
        const loginForm = document.getElementById("login-form");
        if (loginForm) {
            loginForm.addEventListener("submit", handleLogin);
        }

        const passkeyBtn = document.getElementById("passkey-login");
        if (passkeyBtn) {
            passkeyBtn.addEventListener("click", handlePasskeyLogin);
        }

        const totpForm = document.getElementById("totp-form");
        if (totpForm) {
            totpForm.addEventListener("submit", handleTOTP);
        }

        const skip2faBtn = document.getElementById("skip-2fa");
        if (skip2faBtn) {
            skip2faBtn.addEventListener("click", () => {
                window.location.href = "/profile";
            });
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", registerHandlers);
    } else {
        registerHandlers();
    }
}

void init();

async function afterLogin(token: string) {
    await setAuthCookie(token);
    window.location.href = "/profile";
}

async function handleLogin(e: Event) {
    e.preventDefault();

    const clientId = getInput("clientId").value;
    const password = getInput("password").value;

    const result = await opaqueLogin(clientId, password);
    if (result.kind === "token") {
        await afterLogin(result.token);
    } else {
        show2FASection(result.sessionId, result.methods);
    }
}

function show2FASection(sessionId: string, methods: string[]) {
    const section = document.getElementById("2fa-section");
    const sidInput = getInput("totp-session-id");
    const totpForm = document.getElementById("totp-form");
    const webauthnBtn = document.getElementById("webauthn-2fa");

    if (!section) return;
    sidInput.value = sessionId;

    if (totpForm) totpForm.style.display = methods.includes("totp") ? "block" : "none";
    if (webauthnBtn) {
        webauthnBtn.style.display = methods.includes("webauthn") ? "inline" : "none";
        webauthnBtn.addEventListener("click", () => handleWebAuthn2FA(sessionId), { once: true });
    }
    section.style.display = "block";
}

async function handleWebAuthn2FA(sessionId: string) {
    const res1 = await fetch("/api/opaque/login/2fa/webauthn/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId }),
    });
    if (!res1.ok) {
        return;
    }
    const { publicKey: credentialAssertion } = await res1.json();

    const credential = await navigator.credentials.get({
        publicKey: credentialAssertion,
    });
    if (!credential) return;

    const res2 = await fetch("/api/opaque/login/2fa/webauthn/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign({}, credential, { sessionId })),
    });
    if (!res2.ok) {
        return;
    }

    const data = await res2.json();
    await afterLogin(data.token);
}

async function handleTOTP(e: Event) {
    e.preventDefault();
    const code = getInput("totp-code").value;
    const sessionId = getInput("totp-session-id").value;

    const res = await fetch("/api/opaque/login/2fa/totp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId, code }),
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    await afterLogin(data.token);
}

async function handlePasskeyLogin() {
    const res1 = await fetch("/api/webauthn/login/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
    });
    if (!res1.ok) throw new Error(await res1.text());
    const { publicKey: credentialAssertion } = await res1.json();

    const credential = await navigator.credentials.get({
        publicKey: credentialAssertion,
    });
    if (!credential) throw new Error("passkey login cancelled");

    const res2 = await fetch("/api/webauthn/login/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
    });
    if (!res2.ok) throw new Error(await res2.text());
    const data = await res2.json();
    await afterLogin(data.token);
}
