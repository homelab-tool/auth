import { defineConfig } from "rolldown";

export default defineConfig({
    input: {
        "pages/login": "internal/server/pages/login/page.ts",
        "pages/register": "internal/server/pages/register/page.ts",
        "pages/enroll": "internal/server/pages/register/enroll.ts",
    },
    output: {
        dir: "internal/server/pages/static/dist",
        format: "esm",
    },
    resolve: {
        modules: ["node_modules"],
    },
});
