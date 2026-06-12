import { test, expect } from "../fixtures";

test("redirect to /login when accessing /profile without cookie", async ({ page, e2e }) => {
    await page.goto(`${e2e.authUrl}/profile`);
    await expect(page).toHaveURL(`${e2e.authUrl}/login`);
});

test("return 401 for /api/whoami without token", async ({ page, e2e }) => {
    const resp = await page.request.get(`${e2e.authUrl}/api/whoami`);
    expect(resp.status()).toBe(401);
});
