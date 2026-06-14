import * as opaque from "@serenity-kit/opaque";

export type KSFPayload = {
    algorithm: string;
    salt: string;
    params: string;
    outputLen: number;
};

export function parseKSF(ksf: KSFPayload) {
    if (ksf.algorithm !== "argon2id" || ksf.outputLen !== 64)
        throw new Error(`unsupported KSF: ${ksf.algorithm}/${ksf.outputLen}`);

    const p = JSON.parse(ksf.params);
    if (
        typeof p.iterations !== "number" ||
        typeof p.memory !== "number" ||
        typeof p.parallelism !== "number"
    )
        throw new Error("invalid KSF params");

    return {
        "argon2id-custom": {
            iterations: p.iterations,
            memory: p.memory,
            parallelism: p.parallelism,
        },
    } as const;
}

export async function opaqueRegistrationFlow<T>(
    clientId: string,
    password: string,
    startUrl: string,
    finishUrl: string,
): Promise<T> {
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
        password,
    });

    const r1 = await fetch(startUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: registrationRequest }),
    });
    if (!r1.ok) throw new Error(await r1.text());
    const body: { registrationResponse: string; ksf: KSFPayload } = await r1.json();

    const { registrationRecord } = opaque.client.finishRegistration({
        clientRegistrationState,
        password,
        registrationResponse: body.registrationResponse,
        identifiers: { client: clientId },
        keyStretching: parseKSF(body.ksf),
    });

    const r2 = await fetch(finishUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, payload: registrationRecord }),
    });
    if (!r2.ok) throw new Error(await r2.text());
    return r2.json();
}
