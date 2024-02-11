import { isSelfAttestationUsed, parseAuthData, replaceIdentifyingInfo } from "./authData";
import { CredTypesAndPubKeyAlg, authenticatorGetAssertion, authenticatorMakeCredential } from "./authenticator";
import { parseAttestationObject } from "./cbor";
import { toBase64Url } from "./cose";
import { getEffectiveDomain, isRegistrableDomainSuffix } from "./domain";

const AUTHENTICATOR_CAPABILITIES = {
    // It's not clear to me if a software authenticator counts as a platform or cross-platform authenticator, but platform is probably a better fit as it's not necessarily cross-platform.
    attachment: 'platform',
    supportsResidentKeys: true,
    supportsUserVerification: true
};

function validateAttestation(attestation: string | undefined): AttestationConveyancePreference {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-publickeycredentialcreationoptions-attestation
    if (attestation === undefined) {
        return 'none';
    }

    const KNOWN_VALUES: AttestationConveyancePreference[] = ['none', 'indirect', 'direct', 'enterprise'];

    if (KNOWN_VALUES.includes(attestation as AttestationConveyancePreference)) {
        return attestation as AttestationConveyancePreference;
    }

    return 'none';
}

async function validateRpId(rpId: string | undefined, effectiveDomain: string) {
    // https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#createCredential
    // Step 7

    if (rpId === undefined || rpId === effectiveDomain) {
        return effectiveDomain;
    }

    const result = await isRegistrableDomainSuffix(rpId, effectiveDomain);
    if (!result) {
        throw new DOMException('RP ID is not a registrable domain suffix of the effective domain', 'SecurityError');
    }

    return rpId;
}

function continueToTimeout() {
    // There is no other authenticator, so this falls through to step 21.
    // A real implementation will obviously need to wait for the timer (which needs to be passed in) to expire before throwing.
    // FIXME: Doing this before the lifetimeTimer has expired is a privacy leak.
    throw new DOMException('Timer expired', 'NotAllowedError');
}

function validateAuthenticatorSelection(authenticatorSelection: PublicKeyCredentialCreationOptions['authenticatorSelection']) {
    if (!authenticatorSelection) {
        return;
    }

    if (authenticatorSelection.authenticatorAttachment && authenticatorSelection.authenticatorAttachment !== AUTHENTICATOR_CAPABILITIES.attachment) {
        continueToTimeout();
    }

    // This is a no-op included for completeness.
    if (authenticatorSelection.residentKey === 'required' && !AUTHENTICATOR_CAPABILITIES.supportsResidentKeys) {
        continueToTimeout();
    }

    // This is a no-op included for completeness.
    if (authenticatorSelection.residentKey === undefined && authenticatorSelection.requireResidentKey && !AUTHENTICATOR_CAPABILITIES.supportsResidentKeys) {
        continueToTimeout();
    }

    // This is a no-op included for completeness.
    if (authenticatorSelection.userVerification && !AUTHENTICATOR_CAPABILITIES.supportsUserVerification) {
        continueToTimeout();
    }
}

// Taken from https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-createCredential for improved compatibility.
function shouldRequireResidentKey(authenticatorSelection: PublicKeyCredentialCreationOptions['authenticatorSelection']) {
    if (!authenticatorSelection) {
        return false;
    }

    if (authenticatorSelection.residentKey === 'required') {
        return true;
    }

    if (authenticatorSelection.residentKey === 'preferred') {
        return AUTHENTICATOR_CAPABILITIES.supportsResidentKeys;
    }

    if (authenticatorSelection.residentKey === 'discouraged') {
        return false;
    }

    return !!authenticatorSelection.requireResidentKey;
}

function shouldRequireUserVerification(userVerification: UserVerificationRequirement | undefined) {
    return userVerification === 'required'
        || (userVerification === 'preferred' && AUTHENTICATOR_CAPABILITIES.supportsUserVerification);
}

function getCredTypesAndPubKeyAlgs(params: PublicKeyCredentialCreationOptions['pubKeyCredParams']): CredTypesAndPubKeyAlg[] {
    const ALLOWED_TYPE = 'public-key';

    if (params.length === 0) {
        return [
            {
                type: ALLOWED_TYPE,
                alg: -7
            },
            {
                type: ALLOWED_TYPE,
                alg: -257
            }
        ];
    }

    const credTypesAndPubKeyAlgs = [];
    for (const current of params) {
        if (current.type !== ALLOWED_TYPE) {
            continue;
        }

        credTypesAndPubKeyAlgs.push({
            type: current.type,
            alg: current.alg
        });
    }

    return credTypesAndPubKeyAlgs;
}

function createClientDataJSON(type: string, challenge: BufferSource, sameOriginWithAncestors: boolean) {
    return JSON.stringify({
        type: type,
        challenge: toBase64Url(challenge),
        origin: window.origin,
        crossOrigin: !sameOriginWithAncestors
        // The optional tokenBinding member is omitted as token binding is not supported.
    });
}

function createClientDataHash(clientDataJSON: string) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientDataJSON));
}

// Although this is supposed to be synchronous, the functions it calls are async.
export async function internalCreate(origin: string, creationOptions: CredentialCreationOptions, sameOriginWithAncestors: boolean): Promise<((global: typeof globalThis) => Promise<Credential>) | null> {
    // https://www.w3.org/TR/credential-management-1/#algorithm-create-cred
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-createCredential
    console.log('Called replacement internal [[Create]]')

    // Step 1
    if (!creationOptions.publicKey) {
        throw new Error('No publicKey configuration options were provided');
    }

    // Step 2
    if (!sameOriginWithAncestors) {
        throw new DOMException('Called cross-origin', 'NotAllowedError');
    }

    // Step 3
    const options = creationOptions.publicKey;

    // TODO: Step 4 - timeout checks and timer initialisation.

    // Step 5
    if (!options.user.id || (options.user.id.byteLength < 1 || options.user.id.byteLength > 64)) {
        throw new TypeError('user.id does not match the required length.');
    }

    // Steps 6 and 7
    const effectiveDomain = getEffectiveDomain(origin);

    // Step 8
    options.rp.id = await validateRpId(options.rp.id, effectiveDomain);

    // Steps 9
    const credTypesAndPubKeyAlgs = getCredTypesAndPubKeyAlgs(options.pubKeyCredParams);

    // Step 10
    if (credTypesAndPubKeyAlgs.length === 0 && options.pubKeyCredParams.length !== 0) {
        throw new DOMException('No supported algorithms were provided', 'NotSupportedError')
    }

    // Steps 11 and 12 - No client extensions are supported.
    const clientExtensions = {};
    // No authenticator extensions are supported.
    const authenticatorExtensions = new Map();

    // Steps 13 and 14
    const clientDataJSON = createClientDataJSON('webauthn.create', options.challenge, sameOriginWithAncestors);

    // Step 15
    const clientDataHash = await createClientDataHash(clientDataJSON);

    // Step 16
    if (creationOptions.signal && creationOptions.signal.aborted) {
        throw new DOMException('Abort signalled', 'AbortError');
    }

    // Steps 17 and 18 are skipped because there is only a single authenticator so they aren't relevant.

    // TODO: Step 19 - start lifetimeTimer

    // Step 20
    // We only really handle the case where an authenticator becomes available.
    // TODO: Handle other cases where relevant.
    // FIXME: Not handling some cases may be a privacy leak.

    // Step 20.available.2
    if (options.authenticatorSelection) {
        validateAuthenticatorSelection(options.authenticatorSelection);
    }

    // Step 20.available.3
    const requireResidentKey = shouldRequireResidentKey(options.authenticatorSelection);

    // Step 20.available.4
    const requireUserVerification = shouldRequireUserVerification(options.authenticatorSelection?.userVerification);

    // Step 20.available.5
    // We choose not to support enterprise attestation.

    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-publickeycredentialcreationoptions-attestation
    // Validate and if necessary override attestation field.
    options.attestation = validateAttestation(options.attestation);

    const enterpriseAttestationPossible = false;

    // Steps 20.available.6 and .7.1 and .7.2
    // We choose not to filter out credentials with different transports.
    const excludeCredentialDescriptorList = options.excludeCredentials;

    // Step 20.available.7.3
    const attestationObjectResult = authenticatorMakeCredential(clientDataHash, options.rp, options.user, requireResidentKey, requireUserVerification, credTypesAndPubKeyAlgs, enterpriseAttestationPossible, authenticatorExtensions, excludeCredentialDescriptorList);

    // Step 20.success.1 is skipped because there's only one authenticator.

    // Step 20.success.2
    const credentialCreationData = {
        attestationObjectResult: attestationObjectResult,
        clientDataJSONResult: clientDataJSON,
        attestationConveyancePreferenceOption: options.attestation,
        clientExtensionResults: clientExtensions
    };

    // Step 20.success.3
    // This is supposed to be a synchronous function, but can't due to functions called in it.
    const constructCredentialAlg = async (global: typeof globalThis) => {
        // May need in step 3.1, will need in 3.3.
        const { fmt, attStmt, authData } = parseAttestationObject(new Uint8Array(credentialCreationData.attestationObjectResult));
        // Needed in step 3.3.
        const { aaguid, credentialId, publicKey, publicKeyAlgorithm } = await parseAuthData(authData);

        // Step 3.1
        const attrPref = credentialCreationData.attestationConveyancePreferenceOption;
        if (attrPref === 'none') {
            if (!isSelfAttestationUsed(fmt, attStmt, aaguid)) {
                credentialCreationData.attestationObjectResult = replaceIdentifyingInfo(authData);
            }
        } else if (attrPref === 'indirect') {
            // We choose not to change anything.
        } else if (attrPref === 'direct' || attrPref === 'enterprise') {
            // Don't change anything.
        }

        // Step 3.2
        // I don't think using global makes a difference, the global object is the same here as where constructCredentialAlg is going to be called.
        const attestationObject = new global.Uint8Array(credentialCreationData.attestationObjectResult).buffer;

        // Step 3.3
        const id = credentialId;

        // Step 3.4
        // Make sure fields are associated with global
        const clientDataJSON = new global.TextEncoder().encode(credentialCreationData.clientDataJSONResult).buffer;
        const authenticatorData = new global.Uint8Array(authData);
        const spkiPublicKey = new global.Uint8Array(publicKey);

        // Can't call PublicKeyCredential's constructor, so instead override an object's prototype.
        const response = global.Object.create(AuthenticatorAttestationResponse.prototype, {
            clientDataJSON: {
                value: clientDataJSON
            },
            attestationObject: {
                value: attestationObject
            },
            getAuthenticatorData: {
                value: () => authenticatorData
            },
            getPublicKey: {
                value: () => spkiPublicKey
            },
            getPublicKeyAlgorithm: {
                value: () => publicKeyAlgorithm
            },
            getTransports: {
                // None of the standard transports fit, as internal requires client-device-specific transport, but there's nothing hardware-based about the communication with a software authenticator.
                value: () => []
            }
        });

        // [[clientExtensionResults]] expects an ArrayBuffer value, and this returns the deserialisation of that, so just round-trip through JSON (which is required to be possible) to get it created with global.
        const clientExtensionResults = global.JSON.parse(global.JSON.stringify(credentialCreationData.clientExtensionResults));
        const pubKeyCred = global.Object.create(PublicKeyCredential.prototype, {
            id: {
                value: toBase64Url(id)
            },
            rawId: {
                value: id
            },
            type: {
                value: 'public-key',
            },
            response: {
                value: response,
            },
            getClientExtensionResults: {
                value: () => clientExtensionResults,
            }
        });

        // Step 3.5
        return pubKeyCred;
    };

    // Step 20.success.4 is skipped because there's only one authenticator.

    // Step 20.success.5
    return constructCredentialAlg;
}

export function internalCollectFromCredentialStore(_origin: string, _options: CredentialRequestOptions, _sameOriginWithAncestors: boolean): Credential[] {
    // https://www.w3.org/TR/credential-management-1/#algorithm-collect-creds
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-publickeycredential-collectfromcredentialstore-slot
    // Although this is supposed to return a set of credentials, Set is pretty useless when storing objects, so just use an array instead.
    console.log('Called replacement internal [[CollectFromCredentialStore]]');
    return [];
}

// Although this is supposed to be synchronous, the functions it calls are async.
// Also note that the Credential Management spec says this returns a Credential, but the WebAuthn spec says it returns a function that returns a Credential.
export async function internalDiscoverFromCredentialStore(origin: string, getOptions: CredentialRequestOptions, sameOriginWithAncestors: boolean): Promise<((global: typeof globalThis) => Promise<Credential>) | null> {
    // https://www.w3.org/TR/credential-management-1/#algorithm-discover-creds
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-discover-from-external-source
    console.log('Called replacement internal [[DiscoverFromCredentialStore]]');

    // Step 1
    if (!getOptions.publicKey) {
        throw new Error('No publicKey configuration options were provided');
    }

    // Step 2
    const options = getOptions.publicKey;

    // TODO: Step 3 - timeout checks and timer initialisation.

    // Steps 4 and 5
    const effectiveDomain = getEffectiveDomain(origin);

    // Step 6
    options.rpId = await validateRpId(options.rpId, effectiveDomain);

    // Steps 7 and 8 - No client extensions are supported.
    const clientExtensions = {};
    // No authenticator extensions are supported.
    const authenticatorExtensions = new Map();

    // Steps 9 and 10.
    const clientDataJSON = createClientDataJSON('webauthn.get', options.challenge, sameOriginWithAncestors);

    // Step 11
    const clientDataHash = await createClientDataHash(clientDataJSON);

    // Step 12
    if (getOptions.signal && getOptions.signal.aborted) {
        throw new DOMException('Abort signalled', 'AbortError');
    }

    // Step 13 skipped because there is only one authenticator.

    // Step 14
    // savedCredentialId is used instead of a savedCredentialIds map because there is only one authenticator.
    const savedCredentialId = undefined;

    // Step 15 skipped because there is only one authenticator.

    // FIXME: Step 16 - not having lifetime timer is a privacy leak.

    // Step 17
    // We only really handle the case where an authenticator becomes available.
    // TODO: Handle other cases where relevant.
    // FIXME: Not handling some cases may be a privacy leak.

    // Step 17.available.1
    if (options.userVerification === 'required' && !AUTHENTICATOR_CAPABILITIES.supportsUserVerification) {
        continueToTimeout();
    }

    // Step 17.available.2
    const requireUserVerification = shouldRequireUserVerification(options.userVerification);

    // Step 17.available.3
    let authenticatorResult;
    if (options.allowCredentials && options.allowCredentials.length > 0) {
        // TODO: Skipped for now because there's currently no way to query the authenticator for credentials matching what's in allowCredentials.
        throw new Error('Unsupported');
    } else {
        authenticatorResult = authenticatorGetAssertion(options.rpId, clientDataHash, requireUserVerification, authenticatorExtensions)
    }

    // Step 17.available.4 skipped

    // Step 17.success.1 is skipped because there's only one authenticator.

    // Step 17.success.2
    const assertionCreationData = {
        credentialIdResult: savedCredentialId ?? authenticatorResult.credentialId,
        clientDataJSONResult: clientDataJSON,
        authenticatorDataResult: authenticatorResult.authenticatorData,
        signatureResult: authenticatorResult.signature,
        userHandleResult: authenticatorResult.userHandle,
        clientExtensionResults: clientExtensions
    };

    // Step 17.success.3
    const constructAssertionAlg = (global: typeof globalThis) => {
        // Make sure fields are associated with global
        const clientDataJSON = new global.TextEncoder().encode(assertionCreationData.clientDataJSONResult).buffer;
        const authenticatorData = new global.Uint8Array(assertionCreationData.authenticatorDataResult);
        const signature = new global.Uint8Array(assertionCreationData.signatureResult);
        const userHandle = assertionCreationData.userHandleResult ? new global.Uint8Array(assertionCreationData.userHandleResult) : null;

        // Can't call PublicKeyCredential's constructor, so instead override an object's prototype.
        const response = global.Object.create(AuthenticatorAssertionResponse.prototype, {
            clientDataJSON: {
                value: clientDataJSON
            },
            authenticatorData: {
                value: authenticatorData
            },
            signature: {
                value: signature
            },
            userHandle: {
                value: userHandle
            }
        });

        const id = new global.Uint8Array(assertionCreationData.credentialIdResult);

        // [[clientExtensionResults]] expects an ArrayBuffer value, and this returns the deserialisation of that, so just round-trip through JSON (which is required to be possible) to get it created with global.
        const clientExtensionResults = global.JSON.parse(global.JSON.stringify(assertionCreationData.clientExtensionResults));

        const pubKeyCred = global.Object.create(PublicKeyCredential.prototype, {
            id: {
                value: toBase64Url(id)
            },
            rawId: {
                value: id
            },
            type: {
                value: 'public-key',
            },
            response: {
                value: response,
            },
            getClientExtensionResults: {
                value: () => clientExtensionResults,
            }
        });

        return pubKeyCred;
    }

    // Step 17.success.4 skipped as there is only one authenticator.

    // Step 17.success.5
    return constructAssertionAlg;
}

export function internalStore(_credential: PublicKeyCredential, _sameOriginWithAncestors: boolean) {
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
