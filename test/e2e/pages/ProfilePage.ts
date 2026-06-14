import type { Page } from "@playwright/test";

export class ProfilePage {
    constructor(
        public readonly page: Page,
        public readonly baseUrl: string,
    ) {}

    get heading() {
        return this.page.locator("h1");
    }

    get detailItems() {
        return this.page.locator("dd");
    }

    get section2FA() {
        return this.page.locator("#profile-2fa");
    }

    get logoutButton() {
        return this.page.locator("button:has-text('Log Out')");
    }
}
