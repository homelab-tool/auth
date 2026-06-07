import { defineConfig } from "rolldown";

export default defineConfig({
    input: "internal/server/pages/layout/auth.js",
    output: {
        dir: "internal/server/pages/static/dist",
        format: "esm",
    },
    resolve: {
        modules: ["node_modules"],
    },
});
