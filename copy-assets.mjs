import { join, extname, basename } from "node:path";
import { hash } from "node:crypto";
import { cpSync, readFileSync, readdirSync, existsSync, writeFileSync } from "node:fs";

const inputDir = join(import.meta.dirname, "internal/server/pages/static/assets");
const outputDir = join(import.meta.dirname, "internal/server/pages/static/dist");
const manifestFile = join(outputDir, "manifest.json");

const manifest = {};

for (const file of readdirSync(inputDir, { withFileTypes: true, recursive: false })) {
    const inputFile = join(file.parentPath, file.name);
    const contents = readFileSync(inputFile);
    const digest = hash("sha1", contents, "hex").slice(0, 16);

    const ext = extname(file.name);
    const base = basename(file.name, ext);
    const outputFileName = `${base}-${digest}${ext}`;
    manifest[file.name] = outputFileName;

    const outputFile = join(outputDir, outputFileName);

    if (!existsSync(outputFile)) {
        console.log(`* copied: ${inputFile} -> ${outputFile}`);
        cpSync(inputFile, outputFile);
    } else {
        console.log(`* up-to-date: ${inputFile} -> ${outputFile}`);
    }
}

const existingManifest = JSON.parse(readFileSync(manifestFile, "utf8"));
const newManifest = Object.assign(existingManifest, manifest);
writeFileSync(manifestFile, JSON.stringify(newManifest));
