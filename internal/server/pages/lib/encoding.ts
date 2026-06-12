export function base64URLToArrayBuffer(base64URL: string): ArrayBuffer {
    const base64 = base64URL.replace(/-/g, "+").replace(/_/g, "/");
    const binaryStr = atob(base64);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
    }
    return bytes.buffer;
}
