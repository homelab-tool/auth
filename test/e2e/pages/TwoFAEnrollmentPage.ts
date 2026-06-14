import type { Page } from "@playwright/test";

export class TwoFAEnrollmentPage {
    constructor(
        public readonly page: Page,
        public readonly baseUrl: string,
    ) {}

    get setupTOTPButton() {
        return this.page.locator("button:has-text('Set Up Authenticator App')");
    }

    get secretCode() {
        return this.page.locator("#totp-section code");
    }

    get totpInput() {
        return this.page.locator("#totp-code");
    }

    get verifyButton() {
        return this.page.locator("button:has-text('Verify')");
    }

    get totpSection() {
        return this.page.locator("#totp-section");
    }

    get webauthnSetupButton() {
        return this.page.locator("#webauthn-2fa-setup");
    }

    get webauthnStatus() {
        return this.page.locator("#webauthn-2fa-status");
    }
}
