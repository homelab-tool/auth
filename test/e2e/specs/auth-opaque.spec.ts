import { test, expect } from "../fixtures";
import { LoginPage } from "../pages/LoginPage";
import { RegisterPage } from "../pages/RegisterPage";
import { ProfilePage } from "../pages/ProfilePage";

test("register, logout and login with OPAQUE", async ({ page, app }) => {
    const register = new RegisterPage(page, app.authUrl);
    const profile = new ProfilePage(page, app.authUrl);

    await test.step("register", async () => {
        await register.goto();
        await register.clientId.fill("opaque-user");
        await register.password.fill("test-password");
        await register.confirm.fill("test-password");
        await register.opaqueSubmitButton.click();
        await expect(register.enrollmentSection).toBeVisible();
        await register.continueToProfileLink.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(profile.heading).toHaveText("Profile");
        await expect(profile.detailItems.nth(0)).toHaveText("opaque-user");
        await expect(profile.detailItems.nth(1)).toHaveText("Password");
    });

    await test.step("logout", async () => {
        await profile.logoutButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/login`);
    });

    await test.step("login", async () => {
        const login = new LoginPage(page, app.authUrl);
        await login.goto();
        await login.clientId.fill("opaque-user");
        await login.password.fill("test-password");
        await login.submitButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(profile.heading).toHaveText("Profile");
    });
});
