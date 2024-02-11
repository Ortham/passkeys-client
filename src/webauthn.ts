import { assert } from "./assert";

export function internalCreate(origin: string, options: CredentialCreationOptions, sameOriginWithAncestors: boolean): ((global: typeof globalThis) => Credential) | null {
    // https://www.w3.org/TR/credential-management-1/#algorithm-create-cred
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-createCredential
    console.log('Called replacement internal [[Create]]')
    return null;
}

export function internalCollectFromCredentialStore(origin: string, options: CredentialRequestOptions, sameOriginWithAncestors: boolean): Credential[] {
    // https://www.w3.org/TR/credential-management-1/#algorithm-collect-creds
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-publickeycredential-collectfromcredentialstore-slot
    // Although this is supposed to return a set of credentials, Set is pretty useless when storing objects, so just use an array instead.
    console.log('Called replacement internal [[CollectFromCredentialStore]]');
    return [];
}

export function internalDiscoverFromCredentialStore(origin: string, options: CredentialRequestOptions, sameOriginWithAncestors: boolean): Credential | null {
    // https://www.w3.org/TR/credential-management-1/#algorithm-discover-creds
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-discover-from-external-source
    console.log('Called replacement internal [[DiscoverFromCredentialStore]]');
    return null;
}

export function internalStore(credential: PublicKeyCredential, sameOriginWithAncestors: boolean) {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-storeCredential
    throw new DOMException('Not supported', 'NotSupportedError');
}

export function internalPreventSilentAccess() {
    // Do nothing.
}

export function isUserVerifyingPlatformAuthenticatorAvailable() {
    return Promise.resolve(true);
}

export function isConditionalMediationAvailable() {
    return Promise.resolve(false);
}
