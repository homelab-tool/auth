import * as opaque from "@serenity-kit/opaque";
import { setAuthCookie } from "../lib/cookie";

const baseUrl = "/api/opaque";

interface OpaqueLoginToken {
    kind: "token";
    token: string;
}

interface OpaqueLogin2FA {
    kind: "2fa";
    sessionId: string;
    methods: string[];
}

type OpaqueLoginResult = OpaqueLoginToken | OpaqueLogin2FA;

function getInput(id: string): HTMLInputElement {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLInputElement)) throw new Error(`element #${id} is not an input`);
    return el;
}

async function opaqueLogin(clientId: string, password: string): Promise<OpaqueLoginResult> {
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
        password,
    });

    const res1 = await fetch(`${baseUrl}/login/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: startLoginRequest }),
    });
    if (!res1.ok) throw new Error(await res1.text());
    const body: {
        loginResponse: string;
        ksf: { algorithm: string; salt: string; params: string; outputLen: number };
    } = await res1.json();
    const loginResponse = body.loginResponse;
    const ksf = body.ksf;

    if (ksf.algorithm !== "argon2id")
        throw new Error(`unsupported KSF algorithm: ${ksf.algorithm}`);
    if (ksf.outputLen !== 64) throw new Error(`unsupported KSF output length: ${ksf.outputLen}`);

    const parsed = JSON.parse(ksf.params);
    if (
        typeof parsed.iterations !== "number" ||
        typeof parsed.memory !== "number" ||
        typeof parsed.parallelism !== "number"
    ) {
        throw new Error("invalid KSF params");
    }
    const ksfParams: { iterations: number; memory: number; parallelism: number } = parsed;
    const keyStretching = {
        "argon2id-custom": {
            iterations: ksfParams.iterations,
            memory: ksfParams.memory,
            parallelism: ksfParams.parallelism,
        },
    } as const;

    const result = opaque.client.finishLogin({
        clientLoginState,
        password,
        loginResponse,
        identifiers: { client: clientId },
        keyStretching,
    });
    if (!result) throw new Error("login failed");

    const { finishLoginRequest } = result;
    const res2 = await fetch(`${baseUrl}/login/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: finishLoginRequest }),
    });
    if (!res2.ok) throw new Error(await res2.text());

    const data = await res2.json();
    if (data.token) return { kind: "token", token: data.token };
    if (data.status === "2fa_required") {
        return {
            kind: "2fa",
            sessionId: data.session_id,
            methods: data.methods,
        };
    }
    throw new Error("unexpected response");
}

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
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", registerHandlers);
    } else {
        registerHandlers();
    }
}

void init();

async function afterLogin(token: string) {
    await setAuthCookie(token);
    window.location.href = "/profile";
}

async function handleLogin(e: Event) {
    e.preventDefault();

    const clientId = getInput("clientId").value;
    const password = getInput("password").value;

    const result = await opaqueLogin(clientId, password);
    if (result.kind === "token") {
        await afterLogin(result.token);
    } else {
        htmx.ajax(
            "GET",
            `/login/2fa/init?session_id=${result.sessionId}&methods=${result.methods.join(",")}`,
            {
                target: "#login-2fa-section",
                swap: "outerHTML",
            },
        );
    }
}

type CredentialRequestOptionsJSON = Omit<
    PublicKeyCredentialRequestOptions,
    "challenge" | "allowCredentials"
> & {
    challenge: string;
    allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, "id"> & { id: string }>;
};

async function handlePasskeyLogin() {
    const res1 = await fetch("/api/webauthn/login/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
    });
    if (!res1.ok) throw new Error(await res1.text());
    const json: { publicKey: CredentialRequestOptionsJSON } = await res1.json();
    const { publicKey } = json;

    const publicKeyCred = {
        ...publicKey,
        challenge: Uint8Array.fromBase64(publicKey.challenge, { alphabet: "base64url" }).buffer,
        allowCredentials: publicKey.allowCredentials?.map<PublicKeyCredentialDescriptor>((cred) =>
            Object.assign({}, cred, {
                id: Uint8Array.fromBase64(cred.id, { alphabet: "base64url" }).buffer,
            }),
        ),
    } as PublicKeyCredentialRequestOptions;

    const credential = await navigator.credentials.get({ publicKey: publicKeyCred });
    if (!credential) throw new Error("passkey login cancelled");

    const res2 = await fetch("/api/webauthn/login/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
    });
    if (!res2.ok) throw new Error(await res2.text());
    const data = await res2.json();
    await afterLogin(data.token);
}
