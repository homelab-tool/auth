import * as opaque from "@serenity-kit/opaque";
import { setAuthCookie } from "../lib/cookie";
import { opaqueRegistrationFlow } from "../lib/opaque";
import { webauthnCreateCredential } from "../lib/webauthn";

function getInput(id: string): HTMLInputElement {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLInputElement)) throw new Error(`element #${id} is not an input`);
    return el;
}

async function handleRegisterOpaque(e: Event) {
    e.preventDefault();

    const clientId = getInput("clientId").value;
    const password = getInput("password").value;
    const confirm = getInput("confirm").value;

    if (password !== confirm) return;

    const { token } = await opaqueRegistrationFlow<{ token: string }>(
        clientId,
        password,
        "/api/opaque/register/start",
        "/api/opaque/register/finish",
    );
    await setAuthCookie(token);
    htmx.ajax("GET", "/register/2fa", { target: "main", swap: "innerHTML" });
}

async function handleRegisterWebAuthn(e: Event) {
    e.preventDefault();

    const displayName = getInput("webauthn-displayName").value;

    const data = await webauthnCreateCredential<{ token: string }>(
        "/api/webauthn/register/start",
        "/api/webauthn/register/finish",
        { displayName },
    );
    if (!data) return;

    await setAuthCookie(data.token);
    htmx.ajax("GET", "/register/2fa", { target: "main", swap: "innerHTML" });
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
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", registerHandlers);
    } else {
        registerHandlers();
    }
}

void init();
