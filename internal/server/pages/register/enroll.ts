import encodeQR from "qr";
import { webauthnCreateCredential } from "../lib/webauthn";

function renderTOTPQR() {
    const qr = document.getElementById("totp-qr");
    const uri = document.getElementById("totp-uri");
    if (!qr || !(uri instanceof HTMLAnchorElement) || !uri.href) return;
    if (qr.hasChildNodes()) return;

    qr.innerHTML = encodeQR(uri.href, "svg", { scale: 4, border: 2 });
}

async function handleWebAuthnSetup() {
    const ok = await webauthnCreateCredential(
        "/api/opaque/register/2fa/webauthn/start",
        "/api/opaque/register/2fa/webauthn/finish",
    );
    if (!ok) return;

    const btn = document.getElementById("webauthn-2fa-setup");
    if (!btn) return;

    const redirect = btn.getAttribute("data-redirect-on-success");
    if (redirect) {
        window.location.href = redirect;
        return;
    }

    const status = document.getElementById("webauthn-2fa-status");
    if (status) {
        status.innerHTML =
            '<strong style="color: green;">✓ Security key set up successfully!</strong>';
    }
    btn.style.display = "none";
}

async function init() {
    function registerHandlers() {
        const webauthnSetupBtn = document.getElementById("webauthn-2fa-setup");
        if (webauthnSetupBtn) {
            webauthnSetupBtn.addEventListener("click", handleWebAuthnSetup);
        }
        renderTOTPQR();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", registerHandlers);
    } else {
        registerHandlers();
    }
    document.addEventListener("htmx:afterSwap", registerHandlers);
}

void init();
