import type { Page } from "@playwright/test";

export class AdminSiteConfigPage {
    constructor(
        public readonly page: Page,
        public readonly baseUrl: string,
    ) {}

    async goto() {
        await this.page.goto(`${this.baseUrl}/admin/site-configs`);
    }

    get hostnameInput() {
        return this.page.locator("#hostname");
    }

    get submitButton() {
        return this.page.locator("form button[type='submit']");
    }

    get siteConfigList() {
        return this.page.locator("#site-config-list");
    }
}
