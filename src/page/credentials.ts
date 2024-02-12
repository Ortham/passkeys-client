import { assert } from "../assert";
import { internalCollectFromCredentialStore, internalCreate, internalDiscoverFromCredentialStore } from "./webauthn";

function isSameOriginWithAncestors() {
    try {
        return window.self.origin === window.top?.origin;
    } catch (err) {
        return false;
    }
}

function requiresUserMediation(_origin: string) {
    // https://www.w3.org/TR/credential-management-1/#origin-requires-user-mediation
    return true;
}

function isMatchableAPriori(_options: CredentialRequestOptions) {
    // https://www.w3.org/TR/credential-management-1/#credentialrequestoptions-matchable-a-priori
    // https://www.w3.org/TR/webauthn-3/#iface-pkcredential
    // Since PublicKeyCredential is all we're interested in, and its [[discovery]] slot value is "remote", return false.
    return false;
}

export function credentialsCreate(options: CredentialCreationOptions): Promise<Credential | null> {
    // https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create
    // https://www.w3.org/TR/credential-management-1/#algorithm-create

    // Step 1 and 2
    assert(window.isSecureContext, 'Current context is not secure');

    // Step 3
    const global = globalThis;

    // Step 4
    const sameOriginWithAncestors = isSameOriginWithAncestors();

    // Step 5 and 6
    // Because we're only in interested in PublicKeyCredential credentials, and because we can't
    // replace its internal methods, don't create a set of objects, just hardcode the replacement
    // for the internal method that we want to call in step 10.1.

    // Step 7
    if (options.signal && options.signal.aborted) {
        return Promise.reject(new DOMException('Abort signalled', 'AbortError'));
    }

    // Step 9
    const origin = window.origin;

    // Step 8, 10 and 11.
    return new Promise(async (resolve, reject) => {
        try {
            // Step 10.1
            const r = await internalCreate(origin, options, sameOriginWithAncestors);

            // Step 10.3
            if (r === null || r instanceof Credential) {
                resolve(r);
            } else {
                // Step 10.4
                assert(typeof r === 'function', 'Expected r to be a function');

                resolve(r(global));
            }
        } catch(r) {
            // Step 10.2
            reject(r);
        }
    });
}

function credentialsCollect(origin: string, options: CredentialRequestOptions, sameOriginWithAncestors: boolean) {
    // https://www.w3.org/TR/credential-management-1/#abstract-opdef-collect-credentials-from-the-credential-store

    // Step 1
    // As mentioned above, use an array for a set of objects.
    const possibleMatches = [];

    // Step 2
    // Because we're only in interested in PublicKeyCredential credentials, and because we can't
    // replace its internal methods, don't create a set of objects, just hardcode the replacement
    // for the internal method that we want to call in step 2.1.

    try {
        // Step 2.1
        const r = internalCollectFromCredentialStore(origin, options, sameOriginWithAncestors);

        // Step 2.3
        assert(Array.isArray(r));

        // Step 2.4
        possibleMatches.push(...r);
    } catch (r) {
        // Step 2.2 - throw instead of return so that we don't need to check if the return value is an error or not.
        throw r;
    }

    // Step 3
    return possibleMatches;
}

export function credentialsGet(options: CredentialRequestOptions): Promise<Credential | null> {
    // https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get
    // https://www.w3.org/TR/credential-management-1/#abstract-opdef-request-a-credential

    // Step 1 and 2
    assert(window.isSecureContext, 'Current context is not secure');

    // Step 3
    if (options.signal && options.signal.aborted) {
        return Promise.reject(new DOMException('Abort signalled', 'AbortError'));
    }

    // Step 5
    const origin = window.origin;

    // Step 6
    const sameOriginWithAncestors = isSameOriginWithAncestors();

    // Steps 4, 7 and 8
    return new Promise(async (resolve, reject) => {
        // Step 7.1
        let credentials: Credential[];
        try {
            credentials = credentialsCollect(origin, options, sameOriginWithAncestors);
        } catch (credentials) {
            // Step 7.2
            reject(credentials);
            return;
        }

        // Step 7.3
        if (credentials.length === 1
            && !requiresUserMediation(origin)
            && isMatchableAPriori(options)
            && options.mediation !== 'required') {
            resolve(credentials[0]!);
            return;
        }

        // Step 7.4
        if (options.mediation === 'silent') {
            resolve(null);
            return;
        }

        // Step 7.5, 7.6 and 7.7
        // These are skipped because WebAuthn requires that no credentials are collected, so there is nothing for the user to choose from at this point.

        // Step 7.8 and 7.9
        try {
            const result = await internalDiscoverFromCredentialStore(origin, options, sameOriginWithAncestors);
            if (result === null) {
                resolve(null);
            } else {
                resolve(result(globalThis));
            }
        } catch (result) {
            reject(result);
        }
    });
}
