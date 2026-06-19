import { test, expect } from "../fixtures";
import { caddyRequest } from "../lib/caddy-client";
import { AdminSiteConfigPage } from "../pages/AdminSiteConfigPage";
import { LoginPage } from "../pages/LoginPage";

test("Caddy forward_auth with Bearer token", async ({ page, app, caddy }) => {
    const login = new LoginPage(page, app.authUrl);

    await test.step("login as admin", async () => {
        await login.goto();
        await login.clientId.fill(app.adminUsername);
        await login.password.fill(app.adminPassword);
        await login.submitButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
    });

    const cookies = await page.context().cookies();
    const token = cookies.find((c) => c.name === "token")!.value;

    await test.step("create site config and grant access", async () => {
        const siteConfig = new AdminSiteConfigPage(page, app.authUrl);
        await siteConfig.goto();
        await siteConfig.hostnameInput.fill("app1.mydomain.test");
        await siteConfig.submitButton.click();
        await expect(siteConfig.siteConfigList).toContainText("app1.mydomain.test");

        await siteConfig.manageButton("app1.mydomain.test").click();
        await siteConfig.groupSelect.selectOption({ label: "Admin" });
        await siteConfig.grantGroupButton.click();
        await expect(siteConfig.siteAccessSection("app1.mydomain.test")).toContainText("Admin");
    });

    await test.step("authorized request", async () => {
        const authorized = await caddyRequest({
            caddyUrl: caddy.caddyUrl,
            host: "app1.mydomain.test",
            token,
        });
        expect(authorized.status).toBe(200);
        expect(authorized.body).toBe("Hello World from caddy!");
    });

    await test.step("unauthorized request (no token)", async () => {
        const unauthorized = await caddyRequest({
            caddyUrl: caddy.caddyUrl,
            host: "app1.mydomain.test",
        });
        expect(unauthorized.status).toBe(401);
    });

    await test.step("unconfigured host", async () => {
        const unconfigured = await caddyRequest({
            caddyUrl: caddy.caddyUrl,
            host: "app2.mydomain.test",
            token,
        });
        expect(unconfigured.status).toBe(401);
    });
});
