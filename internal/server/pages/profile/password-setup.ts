import * as opaque from "@serenity-kit/opaque";
import { opaqueRegistrationFlow } from "../lib/opaque";

function getInput(id: string): HTMLInputElement {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLInputElement)) throw new Error(`element #${id} is not an input`);
    return el;
}

async function init() {
    await opaque.ready;
    const form = document.getElementById("password-setup-form");
    if (!form) return;
    form.addEventListener("submit", handlePasswordSetup);
}

void init();

async function handlePasswordSetup(e: Event) {
    e.preventDefault();

    const clientId = getInput("password-clientId").value;
    const password = getInput("password-pw").value;
    const confirm = getInput("password-confirm").value;
    if (password !== confirm) return;

    await opaqueRegistrationFlow(
        clientId,
        password,
        "/api/opaque/password/add/start",
        "/api/opaque/password/add/finish",
    );

    window.location.href = "/profile";
}
