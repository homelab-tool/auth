import { defineConfig } from "rolldown";

export default defineConfig({
    input: {
        "pages/login": "internal/server/pages/login/page.ts",
        "pages/register": "internal/server/pages/register/page.ts",
        "pages/enroll": "internal/server/pages/register/enroll.ts",
        "pages/login-2fa": "internal/server/pages/login/2fa.ts",
        "pages/password-setup": "internal/server/pages/profile/password-setup.ts",
        "pages/add-passkey": "internal/server/pages/profile/add-passkey.ts",
    },
    output: {
        dir: "internal/server/pages/static/dist",
        format: "esm",
        minify: true,
        sourcemap: true,
        cleanDir: true,
    },
    resolve: {
        modules: ["node_modules"],
    },
});
