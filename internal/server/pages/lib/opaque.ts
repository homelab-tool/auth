import * as opaque from "@serenity-kit/opaque";

const baseUrl = "/api/opaque";

export interface OpaqueLoginToken {
    kind: "token";
    token: string;
}

export interface OpaqueLogin2FA {
    kind: "2fa";
    sessionId: string;
    methods: string[];
}

export type OpaqueLoginResult = OpaqueLoginToken | OpaqueLogin2FA;

export async function opaqueRegister(clientId: string, password: string): Promise<void> {
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
        password,
    });

    const res1 = await fetch(`${baseUrl}/register/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: registrationRequest }),
    });
    if (!res1.ok) throw new Error(await res1.text());
    const registrationResponse = await res1.text();

    const { registrationRecord } = opaque.client.finishRegistration({
        clientRegistrationState,
        password,
        registrationResponse,
    });

    const res2 = await fetch(`${baseUrl}/register/finish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: registrationRecord }),
    });
    if (!res2.ok) throw new Error(await res2.text());
}

export async function opaqueLogin(clientId: string, password: string): Promise<OpaqueLoginResult> {
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({
        password,
    });

    const res1 = await fetch(`${baseUrl}/login/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: startLoginRequest }),
    });
    if (!res1.ok) throw new Error(await res1.text());
    const loginResponse = await res1.text();

    const result = opaque.client.finishLogin({
        clientLoginState,
        password,
        loginResponse,
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

export const opaqueReady = opaque.ready;
