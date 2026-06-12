import { defineConfig } from "@playwright/test";
import { NAVIGATION_MS, EXPECT_MS, TEST_TIMEOUT_MS } from "./test/e2e/timeouts";

export default defineConfig({
    testDir: "./test/e2e/specs",
    fullyParallel: true,
    timeout: TEST_TIMEOUT_MS,
    expect: { timeout: EXPECT_MS },
    use: {
        trace: {
            mode: "on",
            attachments: true,
            screenshots: true,
            snapshots: true,
            sources: true,
        },
        navigationTimeout: NAVIGATION_MS,
        ignoreHTTPSErrors: true,
        launchOptions: {
            args: ["--host-resolver-rules=MAP *.mydomain.test 127.0.0.1"],
        },
    },
    projects: [
        {
            name: "chromium",
            use: { channel: "chromium" },
        },
    ],
    reporter: [["list"], ["html", { open: "never" }]],
});
