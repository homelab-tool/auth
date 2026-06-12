import * as opaque from "@serenity-kit/opaque";
import { setAuthCookie } from "../lib/cookie";

const baseUrl = "/api/opaque";

function getInput(id: string): HTMLInputElement {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLInputElement)) throw new Error(`element #${id} is not an input`);
    return el;
}

async function opaqueRegister(clientId: string, password: string): Promise<{ token: string }> {
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
        password,
    });

    const res1 = await fetch(`${baseUrl}/register/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: registrationRequest }),
    });
    if (!res1.ok) throw new Error(await res1.text());
    const registrationResponse = await res1.text();

    // Pass clientId as the client identifier so the envelope is sealed with
    // an identity matching what the Go server uses (ClientIdentity field in
    // bytemare's ClientRecord). Both registration and login must use the same
    // identifier, otherwise the envelope HMAC check in ClientLogin::finish
    // (opaque-ke) will fail.
    // Explicit argon2id parameters matching bytemare/ksf defaults
    // (t_cost=3, m_cost=65536, parallelism=4). Both registration and login
    // must use identical key stretching — the protocol derives the masking
    // and envelope keys from KSF(password). A mismatch between the two
    // callsites would produce different derived keys.
    const keyStretching = {
        "argon2id-custom": {
            iterations: 3,
            memory: 65536,
            parallelism: 4,
        },
    } as const;

    const { registrationRecord } = opaque.client.finishRegistration({
        clientRegistrationState,
        password,
        registrationResponse,
        identifiers: { client: clientId },
        keyStretching,
    });

    const res2 = await fetch(`${baseUrl}/register/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: registrationRecord }),
    });
    if (!res2.ok) throw new Error(await res2.text());
    return res2.json();
}

async function init() {
    await opaque.ready;

    function registerHandlers() {
        const opaqueForm = document.getElementById("register-opaque-form");
        if (opaqueForm) {
            opaqueForm.addEventListener("submit", handleRegisterOpaque);
        }

        const webauthnForm = document.getElementById("register-webauthn-form");
        if (webauthnForm) {
            webauthnForm.addEventListener("submit", handleRegisterWebAuthn);
        }

        const totpSetupBtn = document.getElementById("totp-setup");
        if (totpSetupBtn) {
            totpSetupBtn.addEventListener("click", handleTOTPSetup);
        }

        const totpVerifyForm = document.getElementById("totp-verify-form");
        if (totpVerifyForm) {
            totpVerifyForm.addEventListener("submit", handleTOTPVerifySetup);
        }

        const webauthnSetupBtn = document.getElementById("webauthn-setup");
        if (webauthnSetupBtn) {
            webauthnSetupBtn.addEventListener("click", handleWebAuthnSetup);
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

async function handleRegisterOpaque(e: Event) {
    e.preventDefault();

    const clientId = getInput("clientId").value;
    const password = getInput("password").value;
    const confirm = getInput("confirm").value;

    if (password !== confirm) return;

	const { token } = await opaqueRegister(clientId, password);
	await setAuthCookie(token);
	window.location.href = "/profile";
}

async function handleRegisterWebAuthn(e: Event) {
    e.preventDefault();

    const displayName = getInput("webauthn-displayName").value;

    const res1 = await fetch("/api/webauthn/register/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ displayName }),
    });
    if (!res1.ok) throw new Error(await res1.text());
    const { publicKey: credentialCreation } = await res1.json();

    const credential = await navigator.credentials.create({
        publicKey: credentialCreation,
    });
    if (!credential) throw new Error("passkey creation cancelled");

    const res2 = await fetch("/api/webauthn/register/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
    });
    if (!res2.ok) throw new Error(await res2.text());
    const data = await res2.json();
    await setAuthCookie(data.token);
    window.location.href = "/profile";
}

async function handleTOTPSetup() {
    const res = await fetch("/api/opaque/register/2fa/totp/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) throw new Error(await res.text());
    const result = await res.json();

    const secretEl = document.getElementById("totp-secret");
    const detailEl = document.getElementById("totp-setup-detail");
    if (secretEl) secretEl.textContent = result.secret;
    if (detailEl) detailEl.style.display = "block";
}

async function handleTOTPVerifySetup(e: Event) {
    e.preventDefault();
    const code = getInput("totp-setup-code").value;

    const res = await fetch("/api/opaque/register/2fa/totp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
    });
    if (!res.ok) throw new Error(await res.text());
    window.location.href = "/profile";
}

async function handleWebAuthnSetup() {
    const res1 = await fetch("/api/opaque/register/2fa/webauthn/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
    });
    if (!res1.ok) {
        throw new Error(await res1.text());
    }
    const { publicKey: credentialCreation } = await res1.json();

    const credential = await navigator.credentials.create({
        publicKey: credentialCreation,
    });
    if (!credential) return;

    const res2 = await fetch("/api/opaque/register/2fa/webauthn/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
    });
    if (!res2.ok) {
        throw new Error(await res2.text());
    }

    window.location.href = "/profile";
}
