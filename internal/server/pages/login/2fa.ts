import { setAuthCookie } from "../lib/cookie";

type CredentialRequestOptionsJSON = Omit<
    PublicKeyCredentialRequestOptions,
    "challenge" | "allowCredentials"
> & {
    challenge: string;
    allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, "id"> & { id: string }>;
};

function toBuffer(b64: string): ArrayBuffer {
    return Uint8Array.fromBase64(b64, { alphabet: "base64url" }).buffer;
}

function toPublicKey(opts: CredentialRequestOptionsJSON): PublicKeyCredentialRequestOptions {
    const { allowCredentials, ...rest } = opts;
    return {
        ...rest,
        challenge: toBuffer(opts.challenge),
        allowCredentials: allowCredentials?.map<PublicKeyCredentialDescriptor>((cred) => {
            return Object.assign({}, cred, { id: toBuffer(cred.id) });
        }),
    };
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
    const json: { publicKey: CredentialRequestOptionsJSON } = await res1.json();
    const { publicKey } = json;

    const credential = await navigator.credentials.get({
        publicKey: toPublicKey(publicKey),
    });
    if (!credential) return;

    const res2 = await fetch(`/api/opaque/login/2fa/webauthn/finish?sessionId=${sessionId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
    });
    if (!res2.ok) {
        return;
    }

    const data = await res2.json();
    await setAuthCookie(data.token);
    window.location.href = "/profile";
}

function init() {
    const btn = document.getElementById("webauthn-2fa");
    if (!btn) return;
    const sessionId = btn.getAttribute("data-session-id");
    if (!sessionId) return;
    btn.addEventListener("click", () => handleWebAuthn2FA(sessionId));
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
} else {
    init();
}

document.addEventListener("htmx:afterSwap", init);
