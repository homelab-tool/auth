export async function setAuthCookie(token: string): Promise<void> {
    await fetch("/auth/set-cookie", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token }).toString(),
    });
}

export async function clearAuthCookie(): Promise<void> {
    await fetch("/auth/logout", { method: "POST" });
}
