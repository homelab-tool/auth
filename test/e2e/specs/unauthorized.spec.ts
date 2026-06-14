import { test, expect } from "../fixtures";

test("redirect to /login when accessing /profile without cookie", async ({ page, app }) => {
    await page.goto(`${app.authUrl}/profile`);
    await expect(page).toHaveURL(`${app.authUrl}/login`);
});

test("return 401 for /api/whoami without token", async ({ page, app }) => {
    const resp = await page.request.get(`${app.authUrl}/api/whoami`);
    expect(resp.status()).toBe(401);
});
