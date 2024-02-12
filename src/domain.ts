import { getRandomBytes, toBase64Url } from "./util";

function isValidIPv4AddressString(hostname: string) {
    // https://url.spec.whatwg.org/#valid-ipv4-address-string
    const parts = hostname.split('.');
    if (parts.length !== 4) {
        return false;
    }

    for (const part of parts) {
        // Must be the shortest possible string of ASCII digits representing a decimal number in the range of 0 and 255 inclusive.
        if (part.length === 0) {
            return false;
        }
        if (part[0] === '0') {
            return false;
        }
        const int = parseInt(part, 10);
        if (isNaN(int) || int < 0 || int > 255) {
            return false;
        }
    }

    return true;
}

function isValidIPv6AddressString(hostname: string) {
    // https://url.spec.whatwg.org/#valid-ipv6-address-string
    // https://datatracker.ietf.org/doc/html/rfc4291#section-2.2

    // These two modifications don't change the address but simplify parsing.
    if (hostname.startsWith(':')) {
        hostname = '0' + hostname;
    }

    if (hostname.endsWith(':')) {
        hostname += '0';
    }

    const parts = hostname.split(':');
    if (parts.length > 8) {
        return false;
    }

    const lastPart = parts.at(-1);
    if (lastPart !== undefined && lastPart.includes('.')) {
        if (!isValidIPv4AddressString(lastPart)) {
            return false;
        }
        if (parts.length > 7) {
            // The IPv4 address takes the place of the last two 16-bit pieces, so there can only be up to 6 other pieces.
            return false;
        }

        parts.pop();
        parts.push('0');
    }

    let compressed = false;
    for (const part of parts) {
        if (part.length === 0) {
            if (compressed) {
                return false;
            }
            compressed = true;
        } else {
            const int = parseInt(part, 16);
            if (isNaN(int) || int < 0 || int > 0xFFFF) {
                return false;
            }
        }
    }

    return true;
}

function isDomain(hostname: string) {
    if (!hostname) {
        // Null, undefined or empty host.
        return false;
    }

    // According to https://url.spec.whatwg.org/#valid-host-string if the valid hostname isn't a valid IPv4 address or a valid IPv6 address wrapped in square brackets, it must be a valid domain.

    if (isValidIPv4AddressString(hostname)) {
        return false;
    }

    if (hostname.length > 2
        && hostname[0] === '['
        && hostname.at(-1) === ']'
        && isValidIPv6AddressString(hostname.substring(1, hostname.length - 1))) {
        return false;
    }

    return true;
}

export function getEffectiveDomain(origin: string) {
    // https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#createCredential

    // Step 5
    // Can be tested with a data URL, e.g. data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==
    if (origin === "null") {
        throw new DOMException('Origin is opaque', 'NotAllowedError');
    }

    // Step 6
    // Performing the validation as described in https://url.spec.whatwg.org/#valid-domain
    // is very complicated, but fortunately the URL class validates its host, so if the host is a domain then it's a valid domain.
    try {
        const effectiveDomain = new URL(origin).hostname;
        if (!isDomain(effectiveDomain)) {
            throw new DOMException('Effective domain is not a valid domain', 'SecurityError');
        }

        return effectiveDomain;
    } catch (err) {
        throw new DOMException('Effective domain is not a valid domain', 'SecurityError');
    }

}

function getPublicSuffixUsingList(hostname: string): string {
    // Browsers include a copy of the public suffix list, but don't directly expose an API for querying it.
    // However, it is used to decide if you're allowed to set a cookie on a domain that you're under, so try setting a cookie and pop off the front of the domain until it no longer works - the string it stopped working for is the public suffix.
    const domainParts = hostname.split('.');

    for (let i = 0; i < domainParts.length; i += 1) {
        const domainToTest = domainParts.slice(i).join('.');

        // This only works when the domain matches the domain of the current origin, which should be fine because it's ultimately the RP ID that's passed in, which must be a match for WebAuthn to work anyway, and this function is only called if it is a suffix of the current effective domain.
        // Generate a random cookie name to avoid possible collisions.
        const cookieName = toBase64Url(getRandomBytes(16));
        const testCookie = `${cookieName}=test; SameSite=Strict; Secure; Domain=${domainToTest}`;

        document.cookie = testCookie;

        const cookies = document.cookie.split('; ');
        const index = cookies.findIndex(cookie => cookie.startsWith(cookieName));

        if (index > -1) {
            // The cookie was stored, remove it.
            document.cookie = `${testCookie}; Max-Age=0`;
        } else {
            // The cookie was not stored.
            return domainToTest;
        }
    }

    throw new Error('Domain did not have a public suffix');
}

function isAsciiString(string: string) {
    if (typeof string !== 'string') {
        return false;
    }

    return /^[\p{ASCII}]+$/u.test(string);
}

async function getPublicSuffix(hostname: string) {
    if (!isDomain(hostname)) {
        return null;
    }

    const trailingDot = hostname.endsWith('.') ? '.' : '';

    const publicSuffix = await getPublicSuffixUsingList(hostname);

    if (!isAsciiString(publicSuffix) || publicSuffix.endsWith('.')) {
        throw new Error('Invalid public suffix');
    }

    return publicSuffix + trailingDot;
}

export async function isRegistrableDomainSuffix(hostSuffixString: string, originalHost: string) {
    // https://html.spec.whatwg.org/multipage/browsers.html#is-a-registrable-domain-suffix-of-or-is-equal-to

    if (hostSuffixString === "") {
        return false;
    }

    try {
        const hostSuffix = new URL(`http://${hostSuffixString}`).hostname;
        if (hostSuffix === originalHost) {
            return true;
        }

        if (!isDomain(hostSuffix) || !isDomain(originalHost)) {
            return false;
        }

        const prefixedHostSuffix = '.' + hostSuffix;
        if (!originalHost.endsWith(prefixedHostSuffix)) {
            return false;
        }

        if (hostSuffix === await getPublicSuffix(hostSuffix)) {
            return false;
        }

        const originalPublicSuffix = await getPublicSuffix(originalHost);
        if (originalPublicSuffix === null) {
            throw new Error('Invalid public suffix for original host');
        }

        if (originalPublicSuffix.endsWith(prefixedHostSuffix)) {
            return false;
        }

        if (!hostSuffix.endsWith(`.${originalPublicSuffix}`)) {
            throw new Error("Host suffix does not end with original host's public suffix");
        }

        return true;
    } catch (err) {
        return false;
    }
}
