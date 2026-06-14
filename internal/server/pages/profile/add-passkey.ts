import { webauthnCreateCredential } from "../lib/webauthn";

function getSelect(id: string): HTMLSelectElement {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLSelectElement)) throw new Error(`element #${id} is not a select`);
    return el;
}

async function init() {
    const form = document.getElementById("add-passkey-form");
    if (!form) return;
    form.addEventListener("submit", handleAddPasskey);
}

void init();

async function handleAddPasskey(e: Event) {
    e.preventDefault();

    const purpose = getSelect("passkey-purpose").value;

    const ok = await webauthnCreateCredential(
        "/api/webauthn/credentials/add/start",
        "/api/webauthn/credentials/add/finish",
        { purpose },
    );
    if (!ok) return;

    window.location.href = "/profile";
}
