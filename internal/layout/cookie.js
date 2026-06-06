/**
 * @param {string} token
 */
export async function setAuthCookie(token) {
  await fetch("/auth/set-cookie", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token }).toString(),
  });
}

export async function clearAuthCookie() {
  await fetch("/auth/logout", { method: "POST" });
}
