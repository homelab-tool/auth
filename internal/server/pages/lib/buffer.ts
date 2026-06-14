export function b64ToBuffer(b64: string): ArrayBuffer {
    return Uint8Array.fromBase64(b64, { alphabet: "base64url" }).buffer;
}

export type CredentialCreationOptionsJSON = Omit<
    PublicKeyCredentialCreationOptions,
    "challenge" | "user"
> & {
    challenge: string;
    user: Omit<PublicKeyCredentialCreationOptions["user"], "id"> & { id: string };
};

export function toCreationPublicKey(
    opts: CredentialCreationOptionsJSON,
): PublicKeyCredentialCreationOptions {
    return {
        ...opts,
        challenge: b64ToBuffer(opts.challenge),
        user: { ...opts.user, id: b64ToBuffer(opts.user.id) },
    };
}

export type CredentialRequestOptionsJSON = Omit<
    PublicKeyCredentialRequestOptions,
    "challenge" | "allowCredentials"
> & {
    challenge: string;
    allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, "id"> & { id: string }>;
};

export function toRequestPublicKey(
    opts: CredentialRequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
    const { allowCredentials, ...rest } = opts;
    return {
        ...rest,
        challenge: b64ToBuffer(opts.challenge),
        allowCredentials: allowCredentials?.map((cred) =>
            Object.assign({}, cred, { id: b64ToBuffer(cred.id) }),
        ),
    };
}
