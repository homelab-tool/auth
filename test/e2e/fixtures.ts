import { test as base, type TestInfo } from "@playwright/test";
import {
    GenericContainer,
    Network,
    type StartedNetwork,
    type StartedTestContainer,
} from "testcontainers";
import https from "node:https";
import { generate as generateTOTP } from "otplib";
import { CONTAINER_STARTUP_MS, CONTAINER_POLL_INTERVAL_MS, CONTAINER_STOP_MS } from "./timeouts";

const caddyfile = [
    "{",
    "    debug",
    "    local_certs",
    "}",
    "",
    "auth.mydomain.test {",
    "    tls internal",
    "    reverse_proxy auth:1337",
    "}",
    "",
    "app1.mydomain.test {",
    "    tls internal",
    "    forward_auth auth:1337 {",
    "        uri /caddy/forward_auth",
    "    }",
    '    respond "Hello World from caddy!"',
    "}",
    "",
    "app2.mydomain.test {",
    "    tls internal",
    "    forward_auth auth:1337 {",
    "        uri /caddy/forward_auth",
    "    }",
    '    respond "App 2"',
    "}",
].join("\n");

export type E2EWorld = {
    authUrl: string;
    caddyUrl: string;
    adminUsername: string;
    adminPassword: string;
};

let sharedNetwork: StartedNetwork | null = null;
let sharedAuth: StartedTestContainer | null = null;
let sharedCaddy: StartedTestContainer | null = null;
let adminCredentials: { username: string; password: string } | null = null;
let authLogCollector: ReturnType<typeof logCollector> | null = null;
let caddyLogCollector: ReturnType<typeof logCollector> | null = null;

function sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
}

function logCollector(): {
    consumer: (stream: NodeJS.ReadableStream) => void;
    getLogs: () => string;
} {
    const lines: string[] = [];
    return {
        consumer: (stream) => {
            stream.on("data", (chunk: Buffer) => lines.push(chunk.toString()));
        },
        getLogs: () => lines.join(""),
    };
}

function httpsGet(url: string, host?: string): Promise<{ ok: boolean }> {
    return new Promise((resolve) => {
        const req = https.get(
            url,
            {
                rejectUnauthorized: false,
                servername: host,
                headers: host ? { Host: host } : undefined,
            },
            (res) => {
                resolve({ ok: res.statusCode === 200 });
                res.resume();
            },
        );
        req.on("error", () => resolve({ ok: false }));
        req.end();
    });
}

async function tryPing(url: string, opts?: { tls?: boolean; host?: string }): Promise<boolean> {
    try {
        if (opts?.tls) {
            const resp = await httpsGet(url, opts?.host);
            return resp.ok;
        }
        const resp = await fetch(url, {
            headers: opts?.host ? { Host: opts.host } : undefined,
        });
        return resp.ok;
    } catch {
        return false;
    }
}

async function waitForHealth(
    container: StartedTestContainer,
    port: number,
    path: string,
    testInfo: TestInfo,
    opts?: { tls?: boolean; host?: string },
): Promise<void> {
    const protocol = opts?.tls ? "https" : "http";
    const url = `${protocol}://127.0.0.1:${container.getMappedPort(port)}${path}`;
    const deadline = Date.now() + CONTAINER_STARTUP_MS;

    while (Date.now() < deadline) {
        // oxlint-disable-next-line no-await-in-loop
        if (await tryPing(url, opts)) return;
        // oxlint-disable-next-line no-await-in-loop
        await sleep(CONTAINER_POLL_INTERVAL_MS);
    }

    throw new Error(`URL ${url} not accessible after ${CONTAINER_STARTUP_MS}ms`);
}

const ESC = String.fromCharCode(27);
const ansiRe = new RegExp(`${ESC}\\[[0-9;]*m`, "g");

function stripAnsi(s: string): string {
    return s.replace(ansiRe, "");
}

function extractAdminCredentials(logs: string): { username: string; password: string } {
    const userMatch = logs.match(/username=(\S+)/);
    const passMatch = logs.match(/password=(\S+)/);

    if (!userMatch || !passMatch) {
        throw new Error("admin credentials not found in container logs");
    }

    const username = stripAnsi(userMatch[1]?.trim() ?? "");
    const password = stripAnsi(passMatch[1]?.trim() ?? "");
    if (!username || !password) {
        throw new Error("admin credentials not found in container logs");
    }

    return { username, password };
}

async function startContainers(testInfo: TestInfo) {
    const network = await new Network().start();
    sharedNetwork = network;

    const hostPort = Math.floor(Math.random() * 30000) + 30000;
    authLogCollector = logCollector();
    sharedAuth = await new GenericContainer("homelab-auth:e2e")
        .withExposedPorts({ host: hostPort, container: 1337 })
        .withNetwork(network)
        .withNetworkAliases("auth")
        .withEnvironment({
            WEBAUTHN_RPID: "localhost",
            WEBAUTHN_RP_ORIGINS: `http://localhost:${hostPort}`,
            ADMIN_USERNAME: "admin",
        })
        .withLogConsumer(authLogCollector.consumer)
        .start();

    await waitForHealth(sharedAuth, 1337, "/health", testInfo);

    adminCredentials = extractAdminCredentials(authLogCollector.getLogs());

    caddyLogCollector = logCollector();
    sharedCaddy = await new GenericContainer("caddy:2-alpine")
        .withExposedPorts(443)
        .withNetwork(network)
        .withNetworkAliases("caddy")
        .withCopyContentToContainer([{ content: caddyfile, target: "/etc/caddy/Caddyfile" }])
        .withLogConsumer(caddyLogCollector.consumer)
        .start();

    await waitForHealth(sharedCaddy, 443, "/health", testInfo, {
        tls: true,
        host: "auth.mydomain.test",
    });
}

async function stopContainers() {
    await sharedCaddy?.stop({ timeout: CONTAINER_STOP_MS });
    await sharedAuth?.stop({ timeout: CONTAINER_STOP_MS });
    await sharedNetwork?.stop();
    sharedNetwork = null;
    sharedAuth = null;
    sharedCaddy = null;
}

process.on("beforeExit", stopContainers);

export const test = base.extend<{
    e2e: E2EWorld;
    totp: { generate: (secret: string) => Promise<string> };
}>({
    e2e: async ({ page }, use, testInfo) => {
        if (!sharedNetwork) {
            await startContainers(testInfo);
        }

        const logs: string[] = [];
        page.on("console", (msg) => logs.push(`[${msg.type()}] ${msg.text()}`));
        page.on("pageerror", (err) => logs.push(`[PAGE_ERROR] ${err}`));

        await use({
            authUrl: `http://localhost:${sharedAuth!.getMappedPort(1337)}`,
            caddyUrl: `https://127.0.0.1:${sharedCaddy!.getMappedPort(443)}`,
            adminUsername: adminCredentials!.username,
            adminPassword: adminCredentials!.password,
        });

        testInfo.attachments.push({
            name: "auth.log",
            contentType: "text/plain",
            body: Buffer.from(authLogCollector!.getLogs()),
        });
        testInfo.attachments.push({
            name: "caddy.log",
            contentType: "text/plain",
            body: Buffer.from(caddyLogCollector!.getLogs()),
        });

        if (logs.length > 0) {
            testInfo.attachments.push({
                name: "browser-console.txt",
                contentType: "text/plain",
                body: Buffer.from(logs.join("\n")),
            });
        }
    },
    // oxlint-disable-next-line no-empty-pattern
    totp: async ({}, use) => {
        void use({ generate: (secret: string) => generateTOTP({ secret }) });
    },
});

export { expect } from "@playwright/test";
