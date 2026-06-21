import { writeFileSync } from "node:fs";
import { defineConfig } from "rolldown";

export default defineConfig({
    input: {
        "pages/login": "./internal/server/pages/login/page.ts",
        "pages/register": "./internal/server/pages/register/page.ts",
        "pages/enroll": "./internal/server/pages/register/enroll.ts",
        "pages/login-2fa": "./internal/server/pages/login/2fa.ts",
        "pages/password-setup": "./internal/server/pages/profile/password-setup.ts",
        "pages/add-passkey": "./internal/server/pages/profile/add-passkey.ts",
    },
    output: {
        dir: "internal/server/pages/static/dist",
        format: "esm",
        minify: true,
        sourcemap: true,
        cleanDir: true,
        entryFileNames: "[name]-[hash].js",
        codeSplitting: {
            groups: [
                {
                    name: "external",
                    test: /node_modules/,
                },
            ],
        },
    },
    resolve: {
        modules: ["node_modules"],
    },
    plugins: [
        {
            name: "manifest",
            writeBundle(_, bundle) {
                const m = {};
                for (const [key, chunk] of Object.entries(bundle)) {
                    if (chunk.type !== "chunk") continue;
                    if (!chunk.isEntry) continue;
                    m[`${chunk.name}.js`] = key;
                }
                writeFileSync(
                    "./internal/server/pages/static/dist/manifest.json",
                    JSON.stringify(m),
                );
            },
        },
    ],
});
