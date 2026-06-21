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

    deleteGroupButton(name: string) {
        return this.groupCard(name).locator("button:has-text('Delete')");
    }

    memberSelect(groupName: string) {
        return this.groupCard(groupName).locator("select[name='user_id']");
    }

    addMemberButton(groupName: string) {
        return this.groupCard(groupName).locator(
            "form:has(select[name='user_id']) button[type='submit']",
        );
    }

    removeMemberButton(groupName: string, displayName: string) {
        return this.groupCard(groupName).locator(
            `li:has-text("${displayName}") button:has-text('Remove')`,
        );
    }
}
