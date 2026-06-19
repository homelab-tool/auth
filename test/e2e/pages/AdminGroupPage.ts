import type { Page } from "@playwright/test";

export class AdminGroupPage {
    constructor(
        public readonly page: Page,
        public readonly baseUrl: string,
    ) {}

    async goto() {
        await this.page.goto(`${this.baseUrl}/admin/groups`);
    }

    get addGroupButton() {
        return this.page.locator("button:has-text('Add Group')");
    }

    get createForm() {
        return this.page.locator("#create-form");
    }

    get nameInput() {
        return this.page.locator("#name");
    }

    get descriptionInput() {
        return this.page.locator("#description");
    }

    get isAdminCheckbox() {
        return this.page.locator("#is_admin");
    }

    get createSubmitButton() {
        return this.page.locator("#create-form button[type='submit']");
    }

    get groupList() {
        return this.page.locator("#group-list");
    }

    groupCard(name: string) {
        return this.page.locator(`article:has(strong:has-text("${name}"))`);
    }

    manageButton(name: string) {
        return this.groupCard(name).locator("button:has-text('Manage')");
    }

    deleteGroupButton(name: string) {
        return this.groupCard(name).locator("button:has-text('Delete')");
    }

    memberSelect() {
        return this.page.locator("select[name='user_id']");
    }

    addMemberButton() {
        return this.page.locator("form:has(select[name='user_id']) button[type='submit']");
    }

    removeMemberButton(displayName: string) {
        return this.page.locator(`li:has-text("${displayName}") button:has-text('Remove')`);
    }

    memberList() {
        return this.page.locator("section[id^='group-detail-'] ul");
    }
}
