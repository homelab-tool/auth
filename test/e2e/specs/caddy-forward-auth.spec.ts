import { test, expect } from "../fixtures";
import { caddyRequest } from "../lib/caddy-client";

test("Caddy forward_auth with Bearer token", async ({ page, e2e }) => {
    await page.goto(`${e2e.authUrl}/register`);
    await page.fill("#clientId", "caddy-user");
    await page.fill("#password", "test-password");
    await page.fill("#confirm", "test-password");
    await page.click("#register-opaque-form button[type='submit']");
    await page.waitForSelector("[id='2fa-setup-section']", { state: "visible" });
    await page.click("#skip-2fa");
    await expect(page).toHaveURL(`${e2e.authUrl}/success`);

    const cookies = await page.context().cookies();
    const token = cookies.find((c) => c.name === "token")!.value;

    const apiResp = await page.request.post(`${e2e.authUrl}/api/site-configs`, {
        headers: { Authorization: `Bearer ${token}` },
        data: { hostname: "app1.mydomain.test" },
    });
    expect(apiResp.status()).toBe(201);

    const authorized = await caddyRequest({
        caddyUrl: e2e.caddyUrl,
        host: "app1.mydomain.test",
        token,
    });
    expect(authorized.status).toBe(200);
    expect(authorized.body).toBe("Hello World from caddy!");

    const unauthorized = await caddyRequest({
        caddyUrl: e2e.caddyUrl,
        host: "app1.mydomain.test",
    });
    expect(unauthorized.status).toBe(401);

    const unconfigured = await caddyRequest({
        caddyUrl: e2e.caddyUrl,
        host: "app2.mydomain.test",
        token,
    });
    expect(unconfigured.status).toBe(401);
});
