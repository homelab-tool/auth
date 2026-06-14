import { webauthnCreateCredential } from "../lib/webauthn";
import { getInput, getSelect } from "../lib/dom";

async function init() {
    const form = document.getElementById("add-passkey-form");
    if (!form) return;
    form.addEventListener("submit", handleAddPasskey);
}

void init();

async function handleAddPasskey(e: Event) {
    e.preventDefault();

    const name = getInput("passkey-name").value;
    const purpose = getSelect("passkey-purpose").value;

    const ok = await webauthnCreateCredential(
        "/api/webauthn/credentials/add/start",
        "/api/webauthn/credentials/add/finish",
        { purpose, name },
    );
    if (!ok) return;

    window.location.href = "/profile";
}
