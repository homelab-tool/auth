import { test, expect } from "../fixtures";
import { LoginPage } from "../pages/LoginPage";
import { RegisterPage } from "../pages/RegisterPage";
import { ProfilePage } from "../pages/ProfilePage";
import { setupVirtualAuthenticator } from "../pages/WebAuthnHelper";

type CrossMethodCase = {
    registered: "password" | "passkey";
    added: "password" | "passkey";
};

const cases: CrossMethodCase[] = [
    { registered: "password", added: "passkey" },
    { registered: "passkey", added: "password" },
];

const needsVA = (c: CrossMethodCase) => c.registered === "passkey" || c.added === "passkey";

for (const c of cases) {
    test(`${c.registered} user can add ${c.added} from profile`, async ({ page, app, context }) => {
        if (needsVA(c)) {
            await setupVirtualAuthenticator(context, page);
        }

        const username = `${c.registered}-add-${c.added}-user`;
        const password = "test-password";

        await test.step("register", async () => {
            const register = new RegisterPage(page, app.authUrl);
            await register.goto();
            if (c.registered === "password") {
                await register.clientId.fill(username);
                await register.password.fill(password);
                await register.confirm.fill(password);
                await register.opaqueSubmitButton.click();
            } else {
                await register.displayName.fill(username);
                await register.webauthnSubmitButton.click();
            }
            await expect(register.enrollmentSection).toBeVisible();
            await register.continueToProfileLink.click();
            await expect(page).toHaveURL(`${app.authUrl}/profile`);
        });

        await test.step(`add ${c.added}`, async () => {
            if (c.added === "password") {
                await expect(page.locator("#profile-password")).toContainText("Password not set");
                await page.locator('a[href="/profile/password"]').click();
                await expect(page).toHaveURL(`${app.authUrl}/profile/password`);

                await page.locator("#password-clientId").fill(username);
                await page.locator("#password-pw").fill(password);
                await page.locator("#password-confirm").fill(password);
                await page.locator("#password-setup-form button[type='submit']").click();
                await expect(page).toHaveURL(`${app.authUrl}/profile`);
                await expect(page.locator("#profile-password")).toContainText("Password set");
            } else {
                await expect(page.locator("#profile-passkeys")).toContainText("No passkeys");
                await page.locator('a[href="/profile/passkey/add"]').click();
                await expect(page).toHaveURL(`${app.authUrl}/profile/passkey/add`);

                await page.locator("#passkey-purpose").selectOption("login");
                await page.locator("#add-passkey-form button[type='submit']").click();
                await expect(page).toHaveURL(`${app.authUrl}/profile`);
                await expect(page.locator("#profile-passkeys")).toContainText("Login");
            }
        });

        await test.step("logout", async () => {
            await new ProfilePage(page, app.authUrl).logoutButton.click();
            await expect(page).toHaveURL(`${app.authUrl}/login`);
        });

        await test.step(`login with ${c.added}`, async () => {
            const login = new LoginPage(page, app.authUrl);
            await login.goto();
            if (c.added === "password") {
                await login.clientId.fill(username);
                await login.password.fill(password);
                await login.submitButton.click();
            } else {
                await login.passkeyButton.click();
            }
            await expect(page).toHaveURL(`${app.authUrl}/profile`);
        });
    });
}
