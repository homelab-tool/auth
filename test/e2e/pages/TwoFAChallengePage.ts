import type { Page } from "@playwright/test";

export class TwoFAChallengePage {
    constructor(
        public readonly page: Page,
        public readonly baseUrl: string,
    ) {}

    get section() {
        return this.page.locator("#login-2fa-section");
    }

    get totpInput() {
        return this.page.locator("#totp-code");
    }

    get submitButton() {
        return this.page.locator("#login-2fa-section button[type='submit']");
    }

    get webauthnButton() {
        return this.page.locator("#webauthn-2fa");
    }
}
