import { test, expect } from "../fixtures";
import { LoginPage } from "../pages/LoginPage";
import { ProfilePage } from "../pages/ProfilePage";

test("admin user created on first start can login", async ({ page, app }) => {
    await test.step("login as admin", async () => {
        expect(app.adminUsername).toBe("admin");

        const login = new LoginPage(page, app.authUrl);
        const profile = new ProfilePage(page, app.authUrl);

        await login.goto();
        await login.clientId.fill(app.adminUsername);
        await login.password.fill(app.adminPassword);
        await login.submitButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(profile.heading).toHaveText("Profile");
        await expect(profile.detailItems.nth(0)).toHaveText(app.adminUsername);
        await expect(profile.detailItems.nth(1)).toHaveText("Password");
    });
});
