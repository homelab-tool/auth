import { test, expect } from "../fixtures";
import { LoginPage } from "../pages/LoginPage";
import { RegisterPage } from "../pages/RegisterPage";
import { ProfilePage } from "../pages/ProfilePage";
import { TwoFAEnrollmentPage } from "../pages/TwoFAEnrollmentPage";
import { TwoFAChallengePage } from "../pages/TwoFAChallengePage";
import { setupVirtualAuthenticator } from "../pages/WebAuthnHelper";

test("enroll WebAuthn 2FA for OPAQUE user", async ({ page, app, context }) => {
    await setupVirtualAuthenticator(context, page);

    const username = "webauthn2fa-user";
    const password = "test-password";

    await test.step("register and navigate to 2FA enrollment", async () => {
        const register = new RegisterPage(page, app.authUrl);
        await register.goto();
        await register.clientId.fill(username);
        await register.password.fill(password);
        await register.confirm.fill(password);
        await register.opaqueSubmitButton.click();
        await expect(register.enrollmentSection).toBeVisible();
    });

    await test.step("set up WebAuthn security key", async () => {
        const enrollment = new TwoFAEnrollmentPage(page, app.authUrl);
        await enrollment.webauthnSetupButton.click();
        await expect(enrollment.webauthnStatus).toContainText("successfully");
    });

    await test.step("verify WebAuthn shows as enabled on profile", async () => {
        const register = new RegisterPage(page, app.authUrl);
        await register.continueToProfileLink.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(new ProfilePage(page, app.authUrl).section2FA).toContainText("Enabled");
    });

    await test.step("logout", async () => {
        await new ProfilePage(page, app.authUrl).logoutButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/login`);
    });

    await test.step("login with password shows 2FA challenge", async () => {
        const login = new LoginPage(page, app.authUrl);
        await login.goto();
        await login.clientId.fill(username);
        await login.password.fill(password);
        await login.submitButton.click();

        const challenge = new TwoFAChallengePage(page, app.authUrl);
        await expect(challenge.section).toBeVisible();
        await expect(challenge.webauthnButton).toBeVisible();
    });

    await test.step("complete login with WebAuthn 2FA", async () => {
        const challenge = new TwoFAChallengePage(page, app.authUrl);
        await challenge.webauthnButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(new ProfilePage(page, app.authUrl).section2FA).toContainText("Enabled");
    });

    await test.step("disable WebAuthn via API and verify", async () => {
        const cookies = await page.context().cookies();
        const token = cookies.find((c) => c.name === "token");
        expect(token).toBeDefined();

        const resp = await page.request.delete(`${app.authUrl}/api/opaque/register/2fa/webauthn`, {
            headers: { Authorization: `Bearer ${token!.value}` },
        });
        expect(resp.status()).toBe(200);

        await page.reload();
        await expect(new ProfilePage(page, app.authUrl).section2FA).toContainText("Not set up");
    });

    await test.step("enable WebAuthn again through profile page", async () => {
        const profile = new ProfilePage(page, app.authUrl);
        await profile.webauthnSetupLink.click();
        await expect(page).toHaveURL(`${app.authUrl}/register/2fa/webauthn`);

        const enrollment = new TwoFAEnrollmentPage(page, app.authUrl);
        await enrollment.webauthnSetupButton.click();

        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(new ProfilePage(page, app.authUrl).section2FA).toContainText("Enabled");
    });
});
