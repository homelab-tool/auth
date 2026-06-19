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

    manageButton(hostname: string) {
        return this.page.locator(
            `li:has(strong:has-text("${hostname}")) button:has-text('Manage')`,
        );
    }

    get groupSelect() {
        return this.page.locator("select[name='group_id']");
    }

    get grantGroupButton() {
        return this.page.locator("form:has(select[name='group_id']) button[type='submit']");
    }

    siteAccessSection(hostname: string) {
        return this.page.locator(`section[id^='site-access-']`);
    }
}
