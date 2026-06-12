import { opaqueRegister, opaqueLogin, opaqueReady } from "../lib/opaque";
import { setAuthCookie } from "../lib/cookie";

function getInput(id: string): HTMLInputElement {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLInputElement)) throw new Error(`element #${id} is not an input`);
    return el;
}

async function init() {
    await opaqueReady;

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
                window.location.href = "/success";
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

function showError(msg: string) {
    const el = document.getElementById("error");
    if (el) el.textContent = msg;
}

async function handleRegisterOpaque(e: Event) {
    e.preventDefault();
    showError("");

    const clientId = getInput("clientId").value;
    const password = getInput("password").value;
    const confirm = getInput("confirm").value;

    if (password !== confirm) {
        showError("passwords do not match");
        return;
    }

    try {
        await opaqueRegister(clientId, password);
        const result = await opaqueLogin(clientId, password);

        if (result.kind === "token") {
            await setAuthCookie(result.token);
            const section = document.getElementById("2fa-setup-section");
            if (section) section.style.display = "block";
        } else {
            const res = await fetch("/api/opaque/login/2fa/totp", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ sessionId: result.sessionId, code: "" }),
            });
            if (!res.ok) throw new Error(await res.text());
            const data = await res.json();
            await setAuthCookie(data.token);
            window.location.href = "/success";
        }
    } catch (err) {
        showError(err instanceof Error ? err.message : "registration failed");
    }
}

async function handleRegisterWebAuthn(e: Event) {
    e.preventDefault();
    showError("");

    const displayName = getInput("webauthn-displayName").value;

    try {
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
        window.location.href = "/success";
    } catch (err) {
        showError(err instanceof Error ? err.message : "passkey registration failed");
    }
}

async function handleTOTPSetup() {
    try {
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
    } catch (err) {
        showError(err instanceof Error ? err.message : "failed to generate totp secret");
    }
}

async function handleTOTPVerifySetup(e: Event) {
    e.preventDefault();
    const code = getInput("totp-setup-code").value;

    try {
        const res = await fetch("/api/opaque/register/2fa/totp/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code }),
        });
        if (!res.ok) throw new Error(await res.text());
        window.location.href = "/success";
    } catch (err) {
        showError(err instanceof Error ? err.message : "invalid code");
    }
}

async function handleWebAuthnSetup() {
    try {
        const res1 = await fetch("/api/opaque/register/2fa/webauthn/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
        });
        if (!res1.ok) {
            showError(await res1.text());
            return;
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
            showError(await res2.text());
            return;
        }

        window.location.href = "/success";
    } catch (err) {
        showError(err instanceof Error ? err.message : "failed to register security key");
    }
}
