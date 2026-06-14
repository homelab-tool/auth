import type { Page } from "@playwright/test";

export class LoginPage {
    constructor(
        public readonly page: Page,
        public readonly baseUrl: string,
    ) {}

    async goto() {
        await this.page.goto(`${this.baseUrl}/login`);
    }

    get clientId() {
        return this.page.locator("#clientId");
    }

    get password() {
        return this.page.locator("#password");
    }

    get submitButton() {
        return this.page.locator("#login-form button[type='submit']");
    }

    get passkeyButton() {
        return this.page.locator("#passkey-login");
    }
}
