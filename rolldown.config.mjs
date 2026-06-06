import { defineConfig } from "rolldown";

export default defineConfig({
    input: "internal/layout/auth.js",
    output: {
        dir: "internal/static/dist",
        format: "esm",
    },
    resolve: {
        modules: ["node_modules"],
    },
});
