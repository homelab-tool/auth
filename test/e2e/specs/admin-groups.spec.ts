import { test, expect } from "../fixtures";
import { AdminGroupPage } from "../pages/AdminGroupPage";
import { LoginPage } from "../pages/LoginPage";
import { ProfilePage } from "../pages/ProfilePage";
import { RegisterPage } from "../pages/RegisterPage";

test("admin groups management", async ({ page, app }) => {
    const login = new LoginPage(page, app.authUrl);

    await test.step("login as admin", async () => {
        await login.goto();
        await login.clientId.fill(app.adminUsername);
        await login.password.fill(app.adminPassword);
        await login.submitButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
    });

    const groups = new AdminGroupPage(page, app.authUrl);

    await test.step("create a non-admin group", async () => {
        await groups.goto();
        await groups.addGroupButton.click();
        await groups.nameInput.fill("Family");
        await groups.descriptionInput.fill("Family members");
        await groups.createSubmitButton.click();
        await expect(groups.groupList).toContainText("Family");
    });

    await test.step("register a test user", async () => {
        const profile = new ProfilePage(page, app.authUrl);
        await profile.goto();
        await profile.logoutButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/login`);

        const register = new RegisterPage(page, app.authUrl);
        await register.goto();
        await register.clientId.fill("family-user");
        await register.password.fill("test-password");
        await register.confirm.fill("test-password");
        await register.opaqueSubmitButton.click();
        await expect(register.enrollmentSection).toBeVisible();
        await register.continueToProfileLink.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);
    });

    await test.step("add member to group", async () => {
        await login.goto();
        await login.clientId.fill(app.adminUsername);
        await login.password.fill(app.adminPassword);
        await login.submitButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);

        await groups.goto();
        await groups.memberSelect("Family").selectOption({ label: "family-user" });
        await groups.addMemberButton("Family").click();
        await expect(groups.groupCard("Family")).toContainText("family-user");
    });

    await test.step("remove member from group", async () => {
        page.once("dialog", (dialog) => dialog.accept());
        await groups.removeMemberButton("Family", "family-user").click();
        await expect(groups.groupCard("Family")).toContainText("No members");
    });

    await test.step("delete the group", async () => {
        page.once("dialog", (dialog) => dialog.accept());
        await groups.deleteGroupButton("Family").click();
        await expect(groups.groupList).not.toContainText("Family");
    });

    await test.step("cannot delete the only admin group", async () => {
        page.once("dialog", (dialog) => dialog.accept());
        await groups.deleteGroupButton("Admin").click();
        await expect(groups.groupList).toContainText("Admin");
    });

    await test.step("non-admin redirected from /admin/groups", async () => {
        const profile = new ProfilePage(page, app.authUrl);
        await profile.goto();
        await profile.logoutButton.click();
        await expect(page).toHaveURL(`${app.authUrl}/login`);

        const register = new RegisterPage(page, app.authUrl);
        await register.goto();
        await register.clientId.fill("non-admin");
        await register.password.fill("test-password");
        await register.confirm.fill("test-password");
        await register.opaqueSubmitButton.click();
        await expect(register.enrollmentSection).toBeVisible();
        await register.continueToProfileLink.click();
        await expect(page).toHaveURL(`${app.authUrl}/profile`);

        await page.goto(`${app.authUrl}/admin/groups`);
        await expect(page).toHaveURL(`${app.authUrl}/login`);
    });

    await test.step("non-admin redirected from /admin/site-configs", async () => {
        await page.goto(`${app.authUrl}/admin/site-configs`);
        await expect(page).toHaveURL(`${app.authUrl}/login`);
    });
});
