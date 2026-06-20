import { test, expect } from "../fixtures";
import { generate as generateTOTP } from "otplib";
import { LoginPage } from "../pages/LoginPage";
import { RegisterPage } from "../pages/RegisterPage";
import { ProfilePage } from "../pages/ProfilePage";
import { TwoFAEnrollmentPage } from "../pages/TwoFAEnrollmentPage";
import { TwoFAChallengePage } from "../pages/TwoFAChallengePage";
import { setupVirtualAuthenticator } from "../pages/WebAuthnHelper";

type TwoFAScenario = {
    primary: "password" | "passkey";
    secondFactor: "totp" | "webauthn";
};

const scenarios: TwoFAScenario[] = [
    { primary: "password", secondFactor: "totp" },
    { primary: "password", secondFactor: "webauthn" },
    { primary: "passkey", secondFactor: "totp" },
];

const needsVA = (s: TwoFAScenario) => s.primary === "passkey" || s.secondFactor === "webauthn";

for (const s of scenarios) {
    test(`enroll ${s.secondFactor} 2FA for ${s.primary} user`, async ({ page, app, context }) => {
        if (needsVA(s)) {
            await setupVirtualAuthenticator(context, page);
        }

        const username = `${s.primary}-${s.secondFactor}-user`;
        const password = "test-password";
        let totpSecret: string | null = null;
        const profile = new ProfilePage(page, app.authUrl);

        await test.step("register", async () => {
            const register = new RegisterPage(page, app.authUrl);
            await register.goto();
            if (s.primary === "password") {
                await register.clientId.fill(username);
                await register.password.fill(password);
                await register.confirm.fill(password);
                await register.opaqueSubmitButton.click();
            } else {
                await register.displayName.fill(username);
                await register.webauthnSubmitButton.click();
            }
            await expect(register.enrollmentSection).toBeVisible();
        });

        await test.step(`set up ${s.secondFactor}`, async () => {
            const enrollment = new TwoFAEnrollmentPage(page, app.authUrl);
            if (s.secondFactor === "totp") {
                await enrollment.setupTOTPButton.click();
                await expect(enrollment.secretCode).toBeVisible();
                totpSecret = await enrollment.secretCode.textContent();
                expect(totpSecret).toBeTruthy();
                const code = await generateTOTP({ secret: totpSecret! });
                await enrollment.totpInput.fill(code);
                await enrollment.verifyButton.click();
                await expect(enrollment.totpSection).toContainText("successfully");
            } else {
                await enrollment.webauthnSetupButton.click();
                await expect(enrollment.webauthnStatus).toContainText("successfully");
            }
        });

        await test.step("verify 2FA enabled on profile", async () => {
            const register = new RegisterPage(page, app.authUrl);
            await register.continueToProfileLink.click();
            await expect(page).toHaveURL(`${app.authUrl}/profile`);
            await expect(profile.section2FA).toContainText("Enabled");
        });

        await test.step("logout", async () => {
            await profile.logoutButton.click();
            await expect(page).toHaveURL(`${app.authUrl}/login`);
        });

        await test.step("login shows 2FA challenge", async () => {
            const login = new LoginPage(page, app.authUrl);
            await login.goto();
            if (s.primary === "password") {
                await login.clientId.fill(username);
                await login.password.fill(password);
                await login.submitButton.click();
            } else {
                await login.passkeyButton.click();
            }

            const challenge = new TwoFAChallengePage(page, app.authUrl);
            await expect(challenge.section).toBeVisible();
            if (s.secondFactor === "totp") {
                await expect(challenge.totpInput).toBeVisible();
            } else {
                await expect(challenge.webauthnButton).toBeVisible();
            }
        });

        await test.step("complete login with 2FA", async () => {
            const challenge = new TwoFAChallengePage(page, app.authUrl);
            if (s.secondFactor === "totp") {
                const code = await generateTOTP({ secret: totpSecret! });
                await challenge.totpInput.fill(code);
                await challenge.submitButton.click();
            } else {
                await challenge.webauthnButton.click();
            }
            await expect(page).toHaveURL(`${app.authUrl}/profile`);
            await expect(profile.section2FA).toContainText("Enabled");
        });

        await test.step("disable and re-enable via profile", async () => {
            page.on("dialog", (d) => d.accept());
            await profile.section2FA.locator("button:has-text('Disable')").click();
            await expect(profile.section2FA).toContainText("Not set up");

            const setupLink =
                s.secondFactor === "totp" ? profile.totpSetupLink : profile.webauthnSetupLink;
            await setupLink.click();
            await expect(page).toHaveURL(
                s.secondFactor === "totp"
                    ? `${app.authUrl}/register/2fa/totp`
                    : `${app.authUrl}/register/2fa/webauthn`,
            );

            const enrollment = new TwoFAEnrollmentPage(page, app.authUrl);
            if (s.secondFactor === "totp") {
                await expect(enrollment.secretCode).toBeVisible();
                totpSecret = await enrollment.secretCode.textContent();
                expect(totpSecret).toBeTruthy();
                const code = await generateTOTP({ secret: totpSecret! });
                await enrollment.totpInput.fill(code);
                await enrollment.verifyButton.click();
            } else {
                await enrollment.webauthnSetupButton.click();
            }
            await expect(page).toHaveURL(`${app.authUrl}/profile`);
            await expect(profile.section2FA).toContainText("Enabled");
        });
    });
}

test("login TOTP rate limiting", async ({ page, app }) => {
    const username = "ratelimit-user";
    const password = "test-password";
    let totpSecret: string | null = null;
    const profile = new ProfilePage(page, app.authUrl);

    await test.step("register user with TOTP", async () => {
        const register = new RegisterPage(page, app.authUrl);
        await register.goto();
        await register.clientId.fill(username);
        await register.password.fill(password);
        await register.confirm.fill(password);
        await register.opaqueSubmitButton.click();
        await expect(register.enrollmentSection).toBeVisible();

        const enrollment = new TwoFAEnrollmentPage(page, app.authUrl);
        await enrollment.setupTOTPButton.click();
        await expect(enrollment.secretCode).toBeVisible();
        totpSecret = await enrollment.secretCode.textContent();
        expect(totpSecret).toBeTruthy();
        const code = await generateTOTP({ secret: totpSecret! });
        await enrollment.totpInput.fill(code);
        await enrollment.verifyButton.click();
        await expect(enrollment.totpSection).toContainText("successfully");

        await register.continueToProfileLink.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(profile.section2FA).toContainText("Enabled");
    });

    await test.step("logout", async () => {
        await profile.logoutButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/login`);
    });

    await test.step("exhaust TOTP attempts with wrong codes", async () => {
        const login = new LoginPage(page, app.authUrl);
        await login.goto();
        await login.clientId.fill(username);
        await login.password.fill(password);
        await login.submitButton.click();

        const challenge = new TwoFAChallengePage(page, app.authUrl);
        await expect(challenge.section).toBeVisible();
        await expect(challenge.totpInput).toBeVisible();

        for (let i = 0; i < 5; i++) {
            await challenge.totpInput.fill("000000");
            await challenge.submitButton.click();
            await expect(challenge.errorMessage).toContainText("Invalid code. Please try again.");
        }

        await challenge.totpInput.fill("000000");
        await challenge.submitButton.click();
        await expect(challenge.errorMessage).toContainText("Too many attempts. Please start over.");
    });

    await test.step("correct code still blocked during rate limit", async () => {
        const challenge = new TwoFAChallengePage(page, app.authUrl);
        const code = await generateTOTP({ secret: totpSecret! });
        await expect(challenge.errorMessage).toBeVisible();
        await challenge.totpInput.fill(code);
        await challenge.submitButton.click();
        await expect(challenge.errorMessage).toContainText("Too many attempts. Please start over.");
    });

    await test.step("fresh login bypasses rate limit", async () => {
        const login = new LoginPage(page, app.authUrl);
        await login.goto();
        await login.clientId.fill(username);
        await login.password.fill(password);
        await login.submitButton.click();

        const challenge = new TwoFAChallengePage(page, app.authUrl);
        await expect(challenge.section).toBeVisible();

        const code = await generateTOTP({ secret: totpSecret! });
        await challenge.totpInput.fill(code);
        await challenge.submitButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
        await expect(profile.section2FA).toContainText("Enabled");
    });
});
