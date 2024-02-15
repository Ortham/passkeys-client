import { assert } from "../assert";
import { isSelfAttestationUsed, parseAuthData, replaceIdentifyingInfo } from "../authData";
import { InvalidStateError, UserCancelledError, authenticatorCancel, authenticatorGetAssertion, authenticatorMakeCredential, lookupCredentialsById } from "./authenticator";
import { parseAttestationObject } from "../cbor/decode";
import { COSE_ALG_ES256, COSE_ALG_RS256 } from "../cose";
import { getEffectiveDomain, isRegistrableDomainSuffix } from "./domain";
import { createHash, getArrayBuffer, toBase64Url } from "../util";
import { AuthenticatorAssertion, CredTypeAndPubKeyAlg } from "../types";

const ALLOWED_CREDENTIAL_TYPE = 'public-key';
const AUTHENTICATOR_ID = "builtin";
// These could be obtained by querying the authenticator through some authenticator-specific API on first connect and caching the answer.
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

function clamp(value: number, min: number, max: number) {
    return Math.max(Math.min(value, max), min);
}

function getTimeout(options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions) {
    const isUserVerificationDiscouraged = ('authenticatorSelection' in options
            && options.authenticatorSelection?.userVerification === 'discouraged')
        || ('userVerification' in options && options.userVerification === 'discouraged');

    if (isUserVerificationDiscouraged) {
        return options.timeout ? clamp(options.timeout, 30_000, 180_000) : 120_000;
    } else {
        return options.timeout ? clamp(options.timeout, 30_000, 600_000) : 300_000;
    }
}

function handleInterrupt(signal: AbortSignal | undefined, timeout: number, issuedRequests: Set<string>): Promise<never> {
    return new Promise((_resolve, reject) => {
        console.log('Starting timer for', timeout, 'ms');
        const timeoutSignal = AbortSignal.timeout(timeout);

        timeoutSignal.addEventListener('abort', async () => {
            if (issuedRequests.has(AUTHENTICATOR_ID)) {
                authenticatorCancel();
                issuedRequests.delete(AUTHENTICATOR_ID);
            }

            reject(new DOMException('Timer expired', 'NotAllowedError'));
        });

        if (signal) {
            signal.addEventListener('abort', async () => {
                if (issuedRequests.has(AUTHENTICATOR_ID)) {
                    authenticatorCancel();
                    issuedRequests.delete(AUTHENTICATOR_ID);
                }

                // In WebAuthn Level 3 this throws options.signal's abort reason.
                reject(new DOMException('Abort signalled', 'AbortError'));
            });
        }

        // TODO: Add the ability for the user to cancel the process through some UI.
    });
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

function validateAuthenticatorSelection(authenticatorSelection: PublicKeyCredentialCreationOptions['authenticatorSelection']) {
    if (!authenticatorSelection) {
        return;
    }

    if (authenticatorSelection.authenticatorAttachment && authenticatorSelection.authenticatorAttachment !== AUTHENTICATOR_CAPABILITIES.attachment) {
        throw new Error('Authenticator attachment does not match specified value');
    }

    // This is a no-op included for completeness.
    if (authenticatorSelection.residentKey === 'required' && !AUTHENTICATOR_CAPABILITIES.supportsResidentKeys) {
        throw new Error('Resident key required but authenticator does not support them');
    }

    // This is a no-op included for completeness.
    if (authenticatorSelection.residentKey === undefined && authenticatorSelection.requireResidentKey && !AUTHENTICATOR_CAPABILITIES.supportsResidentKeys) {
        throw new Error('Resident key required but authenticator does not support them');
    }

    // This is a no-op included for completeness.
    if (authenticatorSelection.userVerification && !AUTHENTICATOR_CAPABILITIES.supportsUserVerification) {
        throw new Error('User verification required but authenticator does not support it');
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

function getCredTypesAndPubKeyAlgs(params: PublicKeyCredentialCreationOptions['pubKeyCredParams']): CredTypeAndPubKeyAlg[] {
    if (params.length === 0) {
        return [
            {
                type: ALLOWED_CREDENTIAL_TYPE,
                alg: COSE_ALG_ES256
            },
            {
                type: ALLOWED_CREDENTIAL_TYPE,
                alg: COSE_ALG_RS256
            }
        ];
    }

    const credTypesAndPubKeyAlgs = [];
    for (const current of params) {
        if (current.type !== ALLOWED_CREDENTIAL_TYPE) {
            continue;
        }

        credTypesAndPubKeyAlgs.push({
            type: current.type,
            alg: current.alg
        });
    }

    return credTypesAndPubKeyAlgs;
}

function createClientDataJSON(type: string, challenge: BufferSource, origin: string, sameOriginWithAncestors: boolean) {
    return JSON.stringify({
        type: type,
        challenge: toBase64Url(challenge),
        origin: origin,
        crossOrigin: !sameOriginWithAncestors
        // The optional tokenBinding member is omitted as token binding is not supported.
    });
}

function createPublicKeyCredential(global: typeof globalThis, id: ArrayBuffer, response: AuthenticatorResponse, clientExtensionResults: Record<string, unknown>): PublicKeyCredential {
    // [[clientExtensionResults]] expects an ArrayBuffer value, and this returns the deserialisation of that, so just round-trip through JSON (which is required to be possible) to get it created with global.
    const copiedResults = global.JSON.parse(global.JSON.stringify(clientExtensionResults));


    let responseJSON: Record<string, unknown>;
    if (response instanceof AuthenticatorAttestationResponse) {
        const publicKey = response.getPublicKey();

        responseJSON = {
            clientDataJSON: toBase64Url(response.clientDataJSON),
            authenticatorData: toBase64Url(response.getAuthenticatorData()),
            transports: response.getTransports(),
            publicKey: publicKey === null ? null : toBase64Url(publicKey),
            publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
            attestationObject: toBase64Url(response.attestationObject)
        }
    } else if (response instanceof AuthenticatorAssertionResponse) {
        responseJSON = {
            clientDataJSON: toBase64Url(response.clientDataJSON),
            authenticatorData: toBase64Url(response.authenticatorData),
            signature: toBase64Url(response.signature),
            userHandle: response.userHandle === null ? null : toBase64Url(response.userHandle),
            // TODO: Add support for this (it's in WebAuthn Level 3)
            attestationObject: null
        };
    }

    return global.Object.create(PublicKeyCredential.prototype, {
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
        authenticatorAttachment: {
            value: null
        },
        getClientExtensionResults: {
            value: () => copiedResults,
        },
        toJSON: {
            value: () => ({
                id: toBase64Url(id),
                rawId: toBase64Url(id),
                response: responseJSON,
                authenticatorAttachment: null,
                clientExtensionResults: copiedResults,
                type: 'public-key'
            })
        }
    });
}

async function invokeMakeCredential(
    options: PublicKeyCredentialCreationOptions,
    clientDataHash: ArrayBuffer,
    credTypesAndPubKeyAlgs: CredTypeAndPubKeyAlg[],
    authenticatorExtensions: Map<unknown, unknown>
): Promise<ArrayBuffer> {
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
    // These two lines are just to satisfy TypeScript.
    assert(options.rp.id !== undefined);
    const rp = { id: options.rp.id, ...options.rp };

    return authenticatorMakeCredential(clientDataHash, rp, options.user, requireResidentKey, requireUserVerification, credTypesAndPubKeyAlgs, enterpriseAttestationPossible, authenticatorExtensions, excludeCredentialDescriptorList);
}

function handleMakeCredentialSuccess(
    options: PublicKeyCredentialCreationOptions,
    clientDataJSON: string,
    clientExtensions: Record<string, unknown>,
    attestationObjectResult: ArrayBuffer
): (global: typeof globalThis) => Promise<Credential> {
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

        const pubKeyCred = createPublicKeyCredential(global, id, response, credentialCreationData.clientExtensionResults);

        // Step 3.5
        return pubKeyCred;
    };

    // Step 20.success.4 is skipped because there's only one authenticator.

    // Step 20.success.5
    return constructCredentialAlg;
}

// Although this is supposed to be synchronous, the functions it calls are async.
export async function internalCreate(
    origin: string,
    creationOptions: CredentialCreationOptions,
    sameOriginWithAncestors: boolean
): Promise<((global: typeof globalThis) => Promise<Credential>) | null> {
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

    // Step 4 - timeout checks and timer initialisation.
    const timeout = getTimeout(options);

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
    const clientDataJSON = createClientDataJSON('webauthn.create', options.challenge, origin, sameOriginWithAncestors);

    // Step 15
    const clientDataHash = await createHash(clientDataJSON);

    // Step 16
    if (creationOptions.signal && creationOptions.signal.aborted) {
        throw new DOMException('Abort signalled', 'AbortError');
    }

    // Step 17
    // Although there's only a single authenticator, the set can be passed into handleInterrupt and changes to its content outside of the function will be visible inside it.
    const issuedRequests = new Set<string>();

    // Step 18
    // There's only one authenticator and it's always available, so there's nothing to do here.

    // Step 19
    const interruptPromise = handleInterrupt(creationOptions.signal, timeout, issuedRequests);

    // Step 20
    const requestPromise = invokeMakeCredential(options, clientDataHash, credTypesAndPubKeyAlgs, authenticatorExtensions);

    // Step 20.available.8
    issuedRequests.add(AUTHENTICATOR_ID);

    const responsePromise = requestPromise.then(attestationObject => {
        // Step 20.success.1
        issuedRequests.delete(AUTHENTICATOR_ID);

        return handleMakeCredentialSuccess(options, clientDataJSON, clientExtensions, attestationObject);
    }).catch(err => {
        console.error('Caught error while running invokeMakeCredential', err);

        issuedRequests.delete(AUTHENTICATOR_ID);

        if (err instanceof UserCancelledError) {
            // There are no other authenticators, so no need to do anything.
        } else if (err instanceof InvalidStateError) {
            // There are no other authenticators to cancel.
            throw new DOMException('Authenticator encountered an invalid state', 'InvalidStateError');
        } else {
            // Nothing else to do.
        }

        // Let the promise reject when the timer runs out.
        return interruptPromise;
    });

    return Promise.race([
        interruptPromise,
        responsePromise
    ]);
}

export function internalCollectFromCredentialStore(
    _origin: string,
    _options: CredentialRequestOptions,
    _sameOriginWithAncestors: boolean
): Credential[] {
    // https://www.w3.org/TR/credential-management-1/#algorithm-collect-creds
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-publickeycredential-collectfromcredentialstore-slot
    // Although this is supposed to return a set of credentials, Set is pretty useless when storing objects, so just use an array instead.
    console.log('Called replacement internal [[CollectFromCredentialStore]]');
    return [];
}

async function invokeGetAssertion(
    options: PublicKeyCredentialRequestOptions,
    clientDataHash: ArrayBuffer,
    savedCredentialIds: Map<string, PublicKeyCredentialDescriptor>,
    authenticatorExtensions: Map<unknown, unknown>
): Promise<AuthenticatorAssertion> {
    assert(options.rpId !== undefined);

    // Step 17.available.1
    if (options.userVerification === 'required' && !AUTHENTICATOR_CAPABILITIES.supportsUserVerification) {
        throw new Error('User verification required but authenticator does not support it');
    }

    // Step 17.available.2
    const requireUserVerification = shouldRequireUserVerification(options.userVerification);

    // Step 17.available.3
    if (options.allowCredentials && options.allowCredentials.length > 0) {
        const allowedCredentialIds = options.allowCredentials
            .filter(c => c.type === ALLOWED_CREDENTIAL_TYPE)
            .map(c => c.id);

        const allowCredentialDescriptorList = await lookupCredentialsById(options.rpId, allowedCredentialIds);

        if (allowCredentialDescriptorList.length === 0) {
            throw new Error('Authenticator does not have any of the allowed credential IDs');
        }

        const distinctTransports = new Set();

        if (allowCredentialDescriptorList.length === 1) {
            savedCredentialIds.set(AUTHENTICATOR_ID, allowCredentialDescriptorList[0]!);
        }

        for (const descriptor of allowCredentialDescriptorList) {
            if (descriptor.transports !== undefined) {
                for (const transport of descriptor.transports) {
                    distinctTransports.add(transport);
                }
            }
        }

        if (distinctTransports.size > 0) {
            // There's only one transport available to use.
            return authenticatorGetAssertion(options.rpId, clientDataHash, requireUserVerification, authenticatorExtensions, allowCredentialDescriptorList);
        } else {
            // There's only one transport available to use.
            return authenticatorGetAssertion(options.rpId, clientDataHash, requireUserVerification, authenticatorExtensions, allowCredentialDescriptorList);
        }
    } else {
        return authenticatorGetAssertion(options.rpId, clientDataHash, requireUserVerification, authenticatorExtensions);
    }
}

function handleGetAssertionSuccess(
    clientDataJSON: string,
    clientExtensions: Record<string, unknown>,
    savedCredentialIds: Map<string, PublicKeyCredentialDescriptor>,
    authenticatorResult: AuthenticatorAssertion
): (global: typeof globalThis) => Credential {
    // Step 17.success.2
    const assertionCreationData = {
        // If the saved credential ID is null, one will be provided in the result, they're mutually exclusive.
        credentialIdResult: savedCredentialIds.get(AUTHENTICATOR_ID)?.id ?? authenticatorResult.credentialId!,
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
            },
            attestationObject: {
                // TODO: Add support for this (it's in WebAuthn Level 3)
                value: null
            }
        });

        const id = new global.Uint8Array(getArrayBuffer(assertionCreationData.credentialIdResult));

        return createPublicKeyCredential(global, id, response, assertionCreationData.clientExtensionResults);
    }

    // Step 17.success.4 skipped as there is only one authenticator.

    // Step 17.success.5
    return constructAssertionAlg;
}

// Although this is supposed to be synchronous, the functions it calls are async.
// Also note that the Credential Management spec says this returns a Credential, but the WebAuthn spec says it returns a function that returns a Credential.
export async function internalDiscoverFromCredentialStore(
    origin: string,
    getOptions: CredentialRequestOptions,
    sameOriginWithAncestors: boolean
): Promise<((global: typeof globalThis) => Credential) | null> {
    // https://www.w3.org/TR/credential-management-1/#algorithm-discover-creds
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-discover-from-external-source
    console.log('Called replacement internal [[DiscoverFromCredentialStore]]');

    // Step 1
    if (!getOptions.publicKey) {
        throw new Error('No publicKey configuration options were provided');
    }

    // Step 2
    const options = getOptions.publicKey;

    // Step 3
    const timeout = getTimeout(options);

    // Steps 4 and 5
    const effectiveDomain = getEffectiveDomain(origin);

    // Step 6
    options.rpId = await validateRpId(options.rpId, effectiveDomain);

    // Steps 7 and 8 - No client extensions are supported.
    const clientExtensions = {};
    // No authenticator extensions are supported.
    const authenticatorExtensions = new Map();

    // Steps 9 and 10.
    const clientDataJSON = createClientDataJSON('webauthn.get', options.challenge, origin, sameOriginWithAncestors);

    // Step 11
    const clientDataHash = await createHash(clientDataJSON);

    // Step 12
    if (getOptions.signal && getOptions.signal.aborted) {
        throw new DOMException('Abort signalled', 'AbortError');
    }

    // Step 13
    // Although there's only a single authenticator, the set can be passed into handleInterrupt and changes to its content outside of the function will be visible inside it.
    const issuedRequests = new Set<string>();

    // Step 14
    // Although there's only a single authenticator, the map can be passed into invokeGetAssertion and changes to its content outside of the function will be visible inside it.
    const savedCredentialIds = new Map<string, PublicKeyCredentialDescriptor>();

    // Step 15 skipped because there is only one authenticator.

    // Step 16
    const interruptPromise = handleInterrupt(getOptions.signal, timeout, issuedRequests);

    // Step 17
    const requestPromise = invokeGetAssertion(options, clientDataHash, savedCredentialIds, authenticatorExtensions);

    // Step 17.available.4
    issuedRequests.add(AUTHENTICATOR_ID);

    const responsePromise = requestPromise.then(assertion => {
        // Step 17.success.1
        issuedRequests.delete(AUTHENTICATOR_ID);

        return handleGetAssertionSuccess(clientDataJSON, clientExtensions, savedCredentialIds, assertion);
    }).catch(err => {
        console.error('Caught error while running invokeGetAssertion', err);

        issuedRequests.delete(AUTHENTICATOR_ID);

        if (err instanceof UserCancelledError) {
            // There are no other authenticators, so no need to do anything.
        } else {
            // Nothing else to do.
        }

        // Let the promise reject when the timer runs out.
        return interruptPromise;
    });

    return Promise.race([
        interruptPromise,
        responsePromise
    ]);
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
