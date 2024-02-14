export const MESSAGE_TARGET_CONTENT_SCRIPT = 'content-script';
export const MESSAGE_TARGET_PAGE_SCRIPT = 'page-script';
export const MESSAGE_TARGET_BACKGROUND_SCRIPT = 'background-script';
export const MESSAGE_TARGET_POPUP_SCRIPT = 'popup-script';

export function toBase64Url(array: Uint8Array | BufferSource): string {
    const u8array = array instanceof Uint8Array
        ? array
        : new Uint8Array(getArrayBuffer(array));

    return btoa(String.fromCharCode(...u8array))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

export function fromBase64Url(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');

    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

export function getArrayBuffer(bufferSource: BufferSource): ArrayBuffer {
    return bufferSource instanceof ArrayBuffer
    ? bufferSource
    : bufferSource.buffer;
}

export function getRandomBytes(count: number) {
    const array = new Uint8Array(count);
    return crypto.getRandomValues(array);
}

export function createHash(data: string) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
}
