import { test, expect } from "../fixtures";
import { LoginPage } from "../pages/LoginPage";
import { RegisterPage } from "../pages/RegisterPage";
import { ProfilePage } from "../pages/ProfilePage";
import { setupVirtualAuthenticator } from "../pages/WebAuthnHelper";

type AuthCase = {
    label: string;
    userField: "clientId" | "displayName";
    loginAction: "opaque" | "webauthn";
};

const cases: AuthCase[] = [
    { label: "password", userField: "clientId", loginAction: "opaque" },
    { label: "passkey", userField: "displayName", loginAction: "webauthn" },
];

for (const c of cases) {
    test(`register, logout and login with ${c.label}`, async ({ page, app, context }) => {
        if (c.loginAction === "webauthn") {
            await setupVirtualAuthenticator(context, page);
        }

        const register = new RegisterPage(page, app.authUrl);
        const profile = new ProfilePage(page, app.authUrl);
        const username = `${c.label}-user`;

        await test.step("register", async () => {
            await register.goto();
            if (c.userField === "clientId") {
                await register.clientId.fill(username);
                await register.password.fill("test-password");
                await register.confirm.fill("test-password");
                await register.opaqueSubmitButton.click();
            } else {
                await register.displayName.fill(username);
                await register.webauthnSubmitButton.click();
            }
            await expect(register.enrollmentSection).toBeVisible();
            await register.continueToProfileLink.click();
            await expect(page).toHaveURL(`${app.authUrl}/profile`);
            await expect(profile.heading).toHaveText("Profile");
            await expect(profile.detailItems.nth(0)).toHaveText(username);
        });

        await test.step("logout", async () => {
            await profile.logoutButton.click();
            await expect(page).toHaveURL(`${app.authUrl}/login`);
        });

        await test.step("login", async () => {
            const login = new LoginPage(page, app.authUrl);
            await login.goto();
            if (c.loginAction === "opaque") {
                await login.clientId.fill(username);
                await login.password.fill("test-password");
                await login.submitButton.click();
            } else {
                await login.passkeyButton.click();
            }
            await expect(page).toHaveURL(`${app.authUrl}/profile`);
            await expect(profile.heading).toHaveText("Profile");
        });
    });
}
