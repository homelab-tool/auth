import type { Page } from "@playwright/test";

export class RegisterPage {
    constructor(
        public readonly page: Page,
        public readonly baseUrl: string,
    ) {}

    async goto() {
        await this.page.goto(`${this.baseUrl}/register`);
    }

    get clientId() {
        return this.page.locator("#clientId");
    }

    get password() {
        return this.page.locator("#password");
    }

    get confirm() {
        return this.page.locator("#confirm");
    }

    get opaqueSubmitButton() {
        return this.page.locator("#register-opaque-form button[type='submit']");
    }

    get displayName() {
        return this.page.locator("#webauthn-displayName");
    }

    get webauthnSubmitButton() {
        return this.page.locator("#register-webauthn-form button[type='submit']");
    }

    get enrollmentSection() {
        return this.page.locator("#enrollment-section");
    }

    get continueToProfileLink() {
        return this.page.locator('a[href="/profile"]');
    }
}
