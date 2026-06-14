import { test, expect } from "../fixtures";
import { caddyRequest } from "../lib/caddy-client";
import { RegisterPage } from "../pages/RegisterPage";

test("Caddy forward_auth with Bearer token", async ({ page, app, caddy }) => {
    const register = new RegisterPage(page, app.authUrl);
    await register.goto();
    await register.clientId.fill("caddy-user");
    await register.password.fill("test-password");
    await register.confirm.fill("test-password");
    await register.opaqueSubmitButton.click();
    await expect(register.enrollmentSection).toBeVisible();
    await register.continueToProfileLink.click();
    await expect(page).toHaveURL(`${app.authUrl}/profile`);

    const cookies = await page.context().cookies();
    const token = cookies.find((c) => c.name === "token")!.value;

    const apiResp = await page.request.post(`${app.authUrl}/api/site-configs`, {
        headers: { Authorization: `Bearer ${token}` },
        data: { hostname: "app1.mydomain.test" },
    });
    expect(apiResp.status()).toBe(201);

    const authorized = await caddyRequest({
        caddyUrl: caddy.caddyUrl,
        host: "app1.mydomain.test",
        token,
    });
    expect(authorized.status).toBe(200);
    expect(authorized.body).toBe("Hello World from caddy!");

    const unauthorized = await caddyRequest({
        caddyUrl: caddy.caddyUrl,
        host: "app1.mydomain.test",
    });
    expect(unauthorized.status).toBe(401);

    const unconfigured = await caddyRequest({
        caddyUrl: caddy.caddyUrl,
        host: "app2.mydomain.test",
        token,
    });
    expect(unconfigured.status).toBe(401);
});
