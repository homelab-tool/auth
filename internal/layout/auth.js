import * as opaque from "@serenity-kit/opaque";
import { opaqueRegister, opaqueLogin } from "./opaque.js";
import { webauthnRegister, webauthnLogin } from "./webauthn.js";
import { totpVerify, generateTOTPSecret, verifyTOTPSetup } from "./totp.js";
import { setAuthCookie } from "./cookie.js";

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

        const registerOpaqueForm = document.getElementById("register-opaque-form");
        if (registerOpaqueForm) {
            registerOpaqueForm.addEventListener("submit", handleRegisterOpaque);
        }

        const registerWebAuthnForm = document.getElementById("register-webauthn-form");
        if (registerWebAuthnForm) {
            registerWebAuthnForm.addEventListener("submit", handleRegisterWebAuthn);
        }

        const totpForm = document.getElementById("totp-form");
        if (totpForm) {
            totpForm.addEventListener("submit", handleTOTP);
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

init();

/** @param {string} msg */
function showError(msg) {
    const el = document.getElementById("error");
    if (el) el.textContent = msg;
}

/** @param {string} token */
async function afterLogin(token) {
    await setAuthCookie(token);
    window.location.href = "/success";
}

/** @param {SubmitEvent} e */
async function handleLogin(e) {
    e.preventDefault();
    showError("");

    const clientId = /** @type {HTMLInputElement} */ (document.getElementById("clientId")).value;
    const password = /** @type {HTMLInputElement} */ (document.getElementById("password")).value;

    try {
        const result = await opaqueLogin(clientId, password);
        if (result.kind === "token") {
            await afterLogin(result.token);
        } else {
            show2FASection(result.sessionId, result.methods);
        }
    } catch (err) {
        showError(err instanceof Error ? err.message : "login failed");
    }
}

/** @param {string} sessionId @param {string[]} methods */
function show2FASection(sessionId, methods) {
    const section = document.getElementById("2fa-section");
    const sidInput = /** @type {HTMLInputElement} */ (document.getElementById("totp-session-id"));
    const totpForm = document.getElementById("totp-form");
    const webauthnBtn = document.getElementById("webauthn-2fa");

    if (!section) return;
    sidInput.value = sessionId;

    if (totpForm) totpForm.style.display = methods.includes("totp") ? "block" : "none";
    if (webauthnBtn) {
        webauthnBtn.style.display = methods.includes("webauthn") ? "inline" : "none";
        webauthnBtn.onclick = () => handleWebAuthn2FA(sessionId);
    }
    section.style.display = "block";
}

/** @param {string} sessionId */
async function handleWebAuthn2FA(sessionId) {
    try {
        const res1 = await fetch("/api/opaque/login/2fa/webauthn/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sessionId }),
        });
        if (!res1.ok) {
            showError(await res1.text());
            return;
        }
        const { publicKey: credentialAssertion } = await res1.json();

        const credential = await navigator.credentials.get({ publicKey: credentialAssertion });
        if (!credential) return;

        const res2 = await fetch("/api/opaque/login/2fa/webauthn/finish", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...credential, sessionId }),
        });
        if (!res2.ok) {
            showError(await res2.text());
            return;
        }

        const data = await res2.json();
        await afterLogin(data.token);
    } catch (err) {
        showError(err instanceof Error ? err.message : "2fa failed");
    }
}

/** @param {SubmitEvent} e */
async function handleTOTP(e) {
    e.preventDefault();
    const code = /** @type {HTMLInputElement} */ (document.getElementById("totp-code")).value;
    const sessionId = /** @type {HTMLInputElement} */ (
        document.getElementById("totp-session-id")
    ).value;

    try {
        const token = await totpVerify(sessionId, code);
        await afterLogin(token);
    } catch (err) {
        showError(err instanceof Error ? err.message : "invalid code");
    }
}

async function handlePasskeyLogin() {
    showError("");
    try {
        const token = await webauthnLogin();
        await afterLogin(token);
    } catch (err) {
        showError(err instanceof Error ? err.message : "passkey login failed");
    }
}

/** @param {SubmitEvent} e */
async function handleRegisterOpaque(e) {
    e.preventDefault();
    showError("");

    const clientId = /** @type {HTMLInputElement} */ (
        document.getElementById("reg-clientId")
    ).value;
    const password = /** @type {HTMLInputElement} */ (
        document.getElementById("reg-password")
    ).value;
    const confirm = /** @type {HTMLInputElement} */ (document.getElementById("reg-confirm")).value;

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
            const token = await totpVerify(result.sessionId, "");
            await afterLogin(token);
        }
    } catch (err) {
        showError(err instanceof Error ? err.message : "registration failed");
    }
}

/** @param {SubmitEvent} e */
async function handleRegisterWebAuthn(e) {
    e.preventDefault();
    showError("");

    const displayName = /** @type {HTMLInputElement} */ (
        document.getElementById("webauthn-displayName")
    ).value;

    try {
        const token = await webauthnRegister(displayName);
        await afterLogin(token);
    } catch (err) {
        showError(err instanceof Error ? err.message : "passkey registration failed");
    }
}

async function handleTOTPSetup() {
    try {
        const result = await generateTOTPSecret();
        const secretEl = document.getElementById("totp-secret");
        const detailEl = document.getElementById("totp-setup-detail");
        if (secretEl) secretEl.textContent = result.secret;
        if (detailEl) detailEl.style.display = "block";
    } catch (err) {
        showError(err instanceof Error ? err.message : "failed to generate totp secret");
    }
}

/** @param {SubmitEvent} e */
async function handleTOTPVerifySetup(e) {
    e.preventDefault();
    const code = /** @type {HTMLInputElement} */ (document.getElementById("totp-setup-code")).value;

    try {
        await verifyTOTPSetup(code);
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

        const credential = await navigator.credentials.create({ publicKey: credentialCreation });
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
