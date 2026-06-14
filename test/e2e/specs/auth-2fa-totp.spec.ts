import { test, expect } from "../fixtures";
import { LoginPage } from "../pages/LoginPage";
import { RegisterPage } from "../pages/RegisterPage";
import { ProfilePage } from "../pages/ProfilePage";
import { TwoFAEnrollmentPage } from "../pages/TwoFAEnrollmentPage";
import { TwoFAChallengePage } from "../pages/TwoFAChallengePage";

test("enroll, verify TOTP required on login, then disable", async ({ page, app, totp }) => {
    const username = "totp-user";
    const password = "test-password";
    let secret: string | null = null;

    await test.step("register and navigate to 2FA enrollment", async () => {
        const register = new RegisterPage(page, app.authUrl);
        await register.goto();
        await register.clientId.fill(username);
        await register.password.fill(password);
        await register.confirm.fill(password);
        await register.opaqueSubmitButton.click();
        await expect(register.enrollmentSection).toBeVisible();
    });

    await test.step("set up TOTP authenticator app", async () => {
        const enrollment = new TwoFAEnrollmentPage(page, app.authUrl);
        await enrollment.setupTOTPButton.click();
        await expect(enrollment.secretCode).toBeVisible();
        secret = await enrollment.secretCode.textContent();
        expect(secret).toBeTruthy();

        const code = await totp.generate(secret!);
        expect(code).toBeTruthy();
        await enrollment.totpInput.fill(code);
        await enrollment.verifyButton.click();
        await expect(enrollment.totpSection).toContainText("successfully");
    });

    await test.step("go to profile and verify TOTP enabled", async () => {
        const register = new RegisterPage(page, app.authUrl);
        await register.skipLink.click();
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
        await expect(challenge.totpInput).toBeVisible();
    });

    await test.step("complete login with TOTP code", async () => {
        const code = await totp.generate(secret!);
        const challenge = new TwoFAChallengePage(page, app.authUrl);
        await challenge.totpInput.fill(code);
        await challenge.submitButton.click();

        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(new ProfilePage(page, app.authUrl).section2FA).toContainText("Enabled");
    });

    await test.step("disable TOTP via API and verify", async () => {
        const cookies = await page.context().cookies();
        const token = cookies.find((c) => c.name === "token");
        expect(token).toBeDefined();

        const resp = await page.request.delete(`${app.authUrl}/api/opaque/register/2fa/totp`, {
            headers: { Authorization: `Bearer ${token!.value}` },
        });
        expect(resp.status()).toBe(200);

        await page.reload();
        await expect(new ProfilePage(page, app.authUrl).section2FA).toContainText("Not set up");
    });
});
