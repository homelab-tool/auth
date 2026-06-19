import { test, expect } from "../fixtures";
import { caddyRequest } from "../lib/caddy-client";
import { AdminSiteConfigPage } from "../pages/AdminSiteConfigPage";
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

    const siteConfig = new AdminSiteConfigPage(page, app.authUrl);
    await siteConfig.goto();
    await siteConfig.hostnameInput.fill("app1.mydomain.test");
    await siteConfig.submitButton.click();
    await expect(siteConfig.siteConfigList).toContainText("app1.mydomain.test");

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
