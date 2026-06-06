const baseUrl = "/api/webauthn";

/**
 * @param {string} displayName
 * @returns {Promise<string>}
 */
export async function webauthnRegister(displayName) {
  const res1 = await fetch(`${baseUrl}/register/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ displayName }),
  });
  if (!res1.ok) throw new Error(await res1.text());
  const credentialCreation = await res1.json();

  const credential = await navigator.credentials.create({
    publicKey: credentialCreation,
  });
  if (!credential) throw new Error("passkey creation cancelled");

  const res2 = await fetch(`${baseUrl}/register/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credential),
  });
  if (!res2.ok) throw new Error(await res2.text());
  const data = await res2.json();
  return /** @type {string} */ (data.token);
}

/**
 * @returns {Promise<string>}
 */
export async function webauthnLogin() {
  const res1 = await fetch(`${baseUrl}/login/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  if (!res1.ok) throw new Error(await res1.text());
  const credentialAssertion = await res1.json();

  const credential = await navigator.credentials.get({
    publicKey: credentialAssertion,
  });
  if (!credential) throw new Error("passkey login cancelled");

  const res2 = await fetch(`${baseUrl}/login/finish`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credential),
  });
  if (!res2.ok) throw new Error(await res2.text());
  const data = await res2.json();
  return /** @type {string} */ (data.token);
}
