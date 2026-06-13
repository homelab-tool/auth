import encodeQR from "qr";

type CredentialCreationOptionsJSON = Omit<
    PublicKeyCredentialCreationOptions,
    "challenge" | "user"
> & {
    challenge: string;
    user: Omit<PublicKeyCredentialCreationOptions["user"], "id"> & { id: string };
};

function renderTOTPQR() {
    const qr = document.getElementById("totp-qr");
    const uri = document.getElementById("totp-uri");
    if (!qr || !(uri instanceof HTMLAnchorElement) || !uri.href) return;
    if (qr.hasChildNodes()) return;

    qr.innerHTML = encodeQR(uri.href, "svg", { scale: 4, border: 2 });
}

async function handleWebAuthnSetup() {
    const res1 = await fetch("/api/opaque/register/2fa/webauthn/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
    });
    if (!res1.ok) {
        return;
    }
    const json: { publicKey: CredentialCreationOptionsJSON } = await res1.json();
    const { publicKey } = json;

    const credential = await navigator.credentials.create({
        publicKey: {
            ...publicKey,
            challenge: Uint8Array.fromBase64(publicKey.challenge, { alphabet: "base64url" }).buffer,
            user: {
                ...publicKey.user,
                id: Uint8Array.fromBase64(publicKey.user.id, { alphabet: "base64url" }).buffer,
            },
        },
    });
    if (!credential) return;

    const res2 = await fetch("/api/opaque/register/2fa/webauthn/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
    });
    if (!res2.ok) {
        return;
    }

    const status = document.getElementById("webauthn-2fa-status");
    if (status) {
        status.innerHTML =
            '<strong style="color: green;">✓ Security key set up successfully!</strong>';
    }
    const btn = document.getElementById("webauthn-2fa-setup");
    if (btn) {
        btn.style.display = "none";
    }
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
