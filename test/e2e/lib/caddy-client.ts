import https from "node:https";

export function caddyRequest(opts: {
    caddyUrl: string;
    host: string;
    token?: string;
}): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
        const url = new URL(opts.caddyUrl);
        const req = https.request(
            {
                hostname: "127.0.0.1",
                port: Number(url.port),
                path: "/",
                method: "GET",
                rejectUnauthorized: false,
                headers: {
                    Host: opts.host,
                    ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}),
                },
            },
            (res) => {
                let body = "";
                res.on("data", (d: string) => (body += d));
                res.on("end", () => resolve({ status: res.statusCode!, body }));
            },
        );
        req.on("error", reject);
        req.end();
    });
}
