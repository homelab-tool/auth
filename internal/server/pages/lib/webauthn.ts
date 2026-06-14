type CredentialCreationOptionsJSON = Omit<
    PublicKeyCredentialCreationOptions,
    "challenge" | "user"
> & {
    challenge: string;
    user: Omit<PublicKeyCredentialCreationOptions["user"], "id"> & { id: string };
};

export async function webauthnCreateCredential<T>(
    startUrl: string,
    finishUrl: string,
    startBody?: Record<string, string>,
): Promise<T | null> {
    const init: RequestInit = {
        method: "POST",
        headers: { "Content-Type": "application/json" },
    };
    if (startBody) init.body = JSON.stringify(startBody);

    const r1 = await fetch(startUrl, init);
    if (!r1.ok) return null;
    const json: { publicKey: CredentialCreationOptionsJSON } = await r1.json();

    const credential = await navigator.credentials.create({
        publicKey: {
            ...json.publicKey,
            challenge: Uint8Array.fromBase64(json.publicKey.challenge, { alphabet: "base64url" })
                .buffer,
            user: {
                ...json.publicKey.user,
                id: Uint8Array.fromBase64(json.publicKey.user.id, { alphabet: "base64url" }).buffer,
            },
        },
    });
    if (!credential) return null;

    const r2 = await fetch(finishUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credential),
    });
    if (!r2.ok) return null;
    return r2.json();
}
