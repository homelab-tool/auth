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
};

let sharedNetwork: StartedNetwork | null = null;
let sharedAuth: StartedTestContainer | null = null;
let sharedCaddy: StartedTestContainer | null = null;

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
        let ok = false;
        try {
            if (opts?.tls) {
                const resp = await httpsGet(url, opts?.host);
                ok = resp.ok;
            } else {
                const resp = await fetch(url, {
                    headers: opts?.host ? { Host: opts.host } : undefined,
                });
                ok = resp.ok;
            }
        } catch {
            /* retry */
        }
        if (ok) return;
        await sleep(CONTAINER_POLL_INTERVAL_MS);
    }

    throw new Error(`URL ${url} not accessible after ${CONTAINER_STARTUP_MS}ms`);
}

async function startContainers(testInfo: TestInfo) {
    const network = await new Network().start();
    sharedNetwork = network;

    const authLogs = logCollector();
    sharedAuth = await new GenericContainer("homelab-auth:e2e")
        .withExposedPorts(1337)
        .withNetwork(network)
        .withNetworkAliases("auth")
        .withEnvironment({
            WEBAUTHN_RPID: "localhost",
            WEBAUTHN_RP_ORIGINS: "http://localhost:1337",
        })
        .withLogConsumer(authLogs.consumer)
        .start();

    try {
        await waitForHealth(sharedAuth, 1337, "/health", testInfo);
    } catch (err) {
        const logs = authLogs.getLogs();
        if (logs) {
            testInfo.attachments.push({
                name: "auth-container-logs",
                contentType: "text/plain",
                body: Buffer.from(logs),
            });
        }
        throw err;
    }

    const caddyLogs = logCollector();
    sharedCaddy = await new GenericContainer("caddy:2-alpine")
        .withExposedPorts(443)
        .withNetwork(network)
        .withNetworkAliases("caddy")
        .withCopyContentToContainer([{ content: caddyfile, target: "/etc/caddy/Caddyfile" }])
        .withLogConsumer(caddyLogs.consumer)
        .start();

    try {
        await waitForHealth(sharedCaddy, 443, "/health", testInfo, {
            tls: true,
            host: "auth.mydomain.test",
        });
    } catch (err) {
        const logs = caddyLogs.getLogs();
        if (logs) {
            testInfo.attachments.push({
                name: "caddy-container-logs",
                contentType: "text/plain",
                body: Buffer.from(logs),
            });
        }
        throw err;
    }
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
    // oxlint-disable-next-line no-empty-pattern
    e2e: async ({}, use, testInfo) => {
        if (!sharedNetwork) {
            await startContainers(testInfo);
        }
        await use({
            authUrl: `http://127.0.0.1:${sharedAuth!.getMappedPort(1337)}`,
            caddyUrl: `https://127.0.0.1:${sharedCaddy!.getMappedPort(443)}`,
        });
    },
    // oxlint-disable-next-line no-empty-pattern
    totp: async ({}, use) => {
        use({ generate: (secret: string) => generateTOTP({ secret }) });
    },
});

export { expect } from "@playwright/test";
