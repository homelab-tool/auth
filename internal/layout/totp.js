const baseUrl = "/api/opaque";

/**
 * @param {string} sessionId
 * @param {string} code
 * @returns {Promise<string>}
 */
export async function totpVerify(sessionId, code) {
    const res = await fetch(`${baseUrl}/login/2fa/totp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId, code }),
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    return /** @type {string} */ (data.token);
}

/**
 * @returns {Promise<{secret:string, uri:string}>}
 */
export async function generateTOTPSecret() {
    const res = await fetch(`${baseUrl}/register/2fa/totp/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
}

/**
 * @param {string} code
 */
export async function verifyTOTPSetup(code) {
    const res = await fetch(`${baseUrl}/register/2fa/totp/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
    });
    if (!res.ok) throw new Error(await res.text());
}
