export const CONTAINER_STARTUP_MS = sec(10);
export const CONTAINER_STOP_MS = sec(5);
export const TEST_TIMEOUT_MS = sec(30);
export const NAVIGATION_MS = sec(1);
export const EXPECT_MS = sec(1);
export const AUTH_FLOW_MS = sec(5);
export const WEBAUTHN_MS = sec(5);
export const CONTAINER_POLL_INTERVAL_MS = 500;

function sec(x: number): number {
    return x * 1000;
}
