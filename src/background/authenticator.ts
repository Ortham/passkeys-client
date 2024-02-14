import { assert } from "../assert";
import { getImportAlgorithm } from "../authData";
import { AuthenticatorAssertion, CredTypeAndPubKeyAlg, PublicKeyCredentialSource } from "../types";
import { concatArrays, encodeMap } from "../cbor/encode";
import { COSE_ALG_ES256, COSE_ALG_RS256, jwkAlgToCoseIdentifier, jwkToCose } from "../cose";
import { createHash, fromBase64Url, getArrayBuffer, getRandomBytes, toBase64Url } from "../util";
import { getAllStoredCredentials, getCredentialOtherUI, getEncryptionKey, getStoredCredentials, incrementSignatureCounter, storeCredential, storeCredentialOtherUI } from "./store";
import { askUserForCreationConsent, askUserForDisclosureConsent, askUserForSelection } from "./user";
import { decodeMap } from "../cbor/decode";


export class UserCancelledError extends Error {}

export class InvalidStateError extends Error {}

export class UnknownError extends Error {}

export class NotSupportedError extends Error {}

export class NotAllowedError extends Error {}

export class ConstraintError extends Error {}

const ALLOWED_CREDENTIAL_TYPE = 'public-key';
const AUTHENTICATOR_CAPABILITIES = {
    // It's not clear to me if a software authenticator counts as a platform or cross-platform authenticator, but platform is probably a better fit as it's not necessarily cross-platform.
    attachment: 'platform',
    supportsResidentKeys: true,
    supportsUserVerification: true,
    supportsServerSideCredentials: true
};

function areBuffersEqual(buffer1: BufferSource, buffer2: BufferSource) {
    if (buffer1.byteLength !== buffer2.byteLength) {
        return false;
    }

    const view1 = new Uint8Array(getArrayBuffer(buffer1));
    const view2 = new Uint8Array(getArrayBuffer(buffer2));

    for (let i = 0; i < view1.byteLength; i += 1) {
        if (view1[i] !== view2[i]) {
            return false;
        }
    }

    return true;
}

function getCredentialEncryptionAlgorithm(jwk: JsonWebKey): Algorithm {
    if (jwk.alg === 'A256GCM') {
        return { name: 'AES-GCM' };
    }

    throw new Error('Unrecognised encryption algorithm: ' + jwk.alg);
}

async function encryptCredential(credential: Omit<PublicKeyCredentialSource, 'id'>): Promise<ArrayBuffer> {
    // Omit the signature counter from the encrypted data as otherwise that couldn't be incremented without changing the credential ID. Same with the username, the website might allow it to be changed.
    const dataToEncrypt = {
        privateKey: credential.privateKey,
        rpId: credential.rpId,
        userHandle: credential.userHandle === null
            ? null
            : toBase64Url(credential.userHandle)
    };
    const json = JSON.stringify(dataToEncrypt);
    const plaintext = new TextEncoder().encode(json);

    const jwk = await getEncryptionKey();
    const algorithm = getCredentialEncryptionAlgorithm(jwk);

    const key = await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['encrypt']);
    const iv = getRandomBytes(12);
    const ciphertext = await crypto.subtle.encrypt({ name: algorithm.name, iv }, key, plaintext);

    // Now encode the IV and ciphertext as CBOR so that the two are structurally separated.
    const map = new Map([['iv', iv], ['data', ciphertext]]);
    return encodeMap(map);
}

async function decryptCredential(credentialId: BufferSource): Promise<Omit<PublicKeyCredentialSource, 'otherUI'>> {
    const buffer = getArrayBuffer(credentialId);
    const map = decodeMap(new Uint8Array(buffer)).value;

    const iv = map.get('iv');
    assert(iv instanceof Uint8Array);

    const ciphertext = map.get('data');
    assert(ciphertext instanceof Uint8Array);

    const jwk = await getEncryptionKey();
    const algorithm = getCredentialEncryptionAlgorithm(jwk);

    const key = await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['decrypt']);

    const plaintext = await crypto.subtle.decrypt({ name: algorithm.name, iv }, key, ciphertext);
    const json = new TextDecoder().decode(plaintext);
    const data = JSON.parse(json);

    return {
        type: 'public-key',
        id: buffer,
        privateKey: data.privateKey,
        rpId: data.rpId,
        userHandle: data.userHandle === null ? null : fromBase64Url(data.userHandle)
    };
}

async function lookupCredentialById(
    credentialId: BufferSource,
    storedCredentials?: PublicKeyCredentialSource[]
): Promise<PublicKeyCredentialSource | null> {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-lookup-credsource-by-credid
    console.log('Called lookupCredentialById');

    // Step 1
    if (AUTHENTICATOR_CAPABILITIES.supportsServerSideCredentials) {
        try {
            const partialCredentialSource = await decryptCredential(credentialId);
            // Now lookup what goes in otherUI from the authenticator's storage.
            const otherUI = await getCredentialOtherUI(getArrayBuffer(credentialId));
            return {
                ...partialCredentialSource,
                otherUI
            };
        } catch (err) {
            console.warn('Credential ID', credentialId, 'does not appear to be an encrypted credential source', err);
        }
    }

    // Step 2
    const credentials = storedCredentials ?? await getAllStoredCredentials();
    const credential = credentials.find(c => areBuffersEqual(credentialId, c.id));
    if (credential !== undefined) {
        return credential;
    }

    // Step 3
    return null;
}

function getKeyGenParams(algorithm: COSEAlgorithmIdentifier): RsaHashedKeyGenParams | EcKeyGenParams {
    if (algorithm === COSE_ALG_RS256) {
        return {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 4096,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: 'SHA-256'
        };
    }

    if (algorithm === COSE_ALG_ES256) {
        return { name: 'ECDSA', namedCurve: 'P-256' };
    }

    throw new Error('Unrecognised algorithm ' + algorithm);
}

async function generateAttestedCredentialData(credentialId: ArrayBuffer, publicKey: CryptoKey): Promise<Uint8Array> {
    // Set the aaguid to all zeroes.
    const aaguid = new Uint8Array(16);

    const credentialIdLength = new Uint8Array(2);
    credentialIdLength[0] = (credentialId.byteLength & 0xFF00) >> 8;
    credentialIdLength[1] = (credentialId.byteLength & 0x00FF);

    const jwt = await crypto.subtle.exportKey('jwk', publicKey);
    const coseKey = jwkToCose(jwt);
    const cborKey = encodeMap(new Map(Object.entries(coseKey)));

    return concatArrays(aaguid, credentialIdLength, new Uint8Array(credentialId), cborKey);
}

function generateFlags(
    userVerified: boolean,
    includesAttestedCredentialData: boolean,
    includesExtensions: boolean
) {
    // WebAuthn requires user presence to be checked, so the flag would always be set.
    let flags = 0b1;

    if (userVerified) {
        flags |= 0b100;
    }

    if (includesAttestedCredentialData) {
        flags |= 0b100_0000;
    }

    if (includesExtensions) {
        flags |= 0b1000_0000;
    }

    return flags;
}

function generateAuthenticatorData(rpIdHash: ArrayBuffer, flags: number, signCount: number, attestedCredentialData: Uint8Array | undefined, extensions: Record<string, unknown>): Uint8Array {
    const signCountArray = new ArrayBuffer(4);
    new DataView(signCountArray).setUint32(0, signCount, false);

    const extensionsMap = new Map(Object.entries(extensions));
    const extensionsArray = extensionsMap.size === 0
        ? new Uint8Array(0)
        : encodeMap(extensionsMap);

    if (attestedCredentialData !== undefined) {
        return concatArrays(
            new Uint8Array(rpIdHash),
            new Uint8Array([flags]),
            new Uint8Array(signCountArray),
            attestedCredentialData,
            extensionsArray
        );
    }

    return concatArrays(
        new Uint8Array(rpIdHash),
        new Uint8Array([flags]),
        new Uint8Array(signCountArray),
        extensionsArray
    );
}

async function generateAttestationObject(privateKey: JsonWebKey, authenticatorData: Uint8Array, hash: ArrayBuffer, enterpriseAttestationPossible: boolean): Promise<Uint8Array> {
    if (enterpriseAttestationPossible) {
        // Enterprise attestation is not supported, do nothing.
    }

    // The authenticator only supports self attestation.
    const signature = await generateSignature(privateKey, authenticatorData, hash);

    const map = new Map();
    map.set('fmt', 'packed');
    map.set('attStmt', {
        alg: jwkAlgToCoseIdentifier(privateKey.alg),
        sig: signature
    });
    map.set('authData', authenticatorData);

    return encodeMap(map);
}


function getSigningAlgorithm(jwk: JsonWebKey): AlgorithmIdentifier | EcdsaParams {
    if (jwk.alg === 'RS256') {
        return { name: 'RSASSA-PKCS1-v1_5' };
    }

    if (jwk.alg === 'ES256') {
        return { name: 'ECDSA', hash: 'SHA-256' };
    }

    throw new Error('Unrecognised algorithm ' + jwk.alg);
}

async function generateSignature(
    privateKey: JsonWebKey,
    authenticatorData: Uint8Array,
    hash: ArrayBuffer
): Promise<ArrayBuffer> {
    const dataToSign = concatArrays(authenticatorData, new Uint8Array(hash));

    const key = await crypto.subtle.importKey('jwk', privateKey, getImportAlgorithm(privateKey), false, ['sign']);

    const signature = await crypto.subtle.sign(getSigningAlgorithm(privateKey), key, dataToSign);

    if (privateKey.kty !== 'EC') {
        return signature;
    }

    // ECDSA signatures need to be DER-encoded.

    assert(signature.byteLength % 2 === 0);
    assert(signature.byteLength < 256);
    const numberLength = signature.byteLength / 2;

    const r = signature.slice(0, numberLength);
    const s = signature.slice(numberLength);

    const DER_TAG_SEQUENCE = 0x30;
    const DER_TAG_INTEGER = 0x02;

    // Plus 2 bytes each for the integer tag and length bytes.
    const sequenceLength = signature.byteLength + 4;

    return concatArrays(
        new Uint8Array([DER_TAG_SEQUENCE, sequenceLength]),
        new Uint8Array([DER_TAG_INTEGER, numberLength]),
        new Uint8Array(r),
        new Uint8Array([DER_TAG_INTEGER, numberLength]),
        new Uint8Array(s)
    );
}

export async function lookupCredentialsById(
    rpId: string,
    allowedCredentialIds: BufferSource[]
): Promise<PublicKeyCredentialDescriptor[]> {
    console.log('Called lookupCredentialsById');

    // Fetch stored credentials for the RP so that they're not retrieved for each credential.
    const credentials = (await getStoredCredentials(rpId)).slice();

    const promises = allowedCredentialIds.map(async id => {
        const credential = await lookupCredentialById(id, credentials);
        if (credential === null || credential.rpId !== rpId) {
            return null;
        }

        return {
            id: credential.id,
            type: credential.type
        };
    });

    const descriptors = await Promise.all(promises);

    return descriptors.filter((c => c !== null)) as PublicKeyCredentialDescriptor[];
}

function findSupportedAlgorithm(credTypesAndPubKeyAlgs: CredTypeAndPubKeyAlg[]): number | undefined {
    const entry = credTypesAndPubKeyAlgs.find(entry =>
        entry.type === ALLOWED_CREDENTIAL_TYPE
            && (entry.alg === COSE_ALG_ES256 || entry.alg === COSE_ALG_RS256)
    );

    return entry?.alg;
}

export async function authenticatorMakeCredential(
    hash: ArrayBuffer,
    rpEntity: Required<PublicKeyCredentialRpEntity>,
    userEntity: PublicKeyCredentialUserEntity,
    requireResidentKey: boolean,
    requireUserVerification: boolean,
    credTypesAndPubKeyAlgs: CredTypeAndPubKeyAlg[],
    enterpriseAttestationPossible: boolean,
    extensions: Map<unknown, unknown>,
    excludeCredentialDescriptorList?: PublicKeyCredentialDescriptor[],
): Promise<ArrayBuffer> {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-make-cred
    console.log('Called authenticatorMakeCredential');

    // Step 1
    // Because there's been no serialisation and deserialisation, hash is the only thing that could be malformed.
    if (hash.byteLength !== 32) {
        throw new UnknownError('Hash length is invalid');
    }

    // Step 2
    const supportedAlgorithm = findSupportedAlgorithm(credTypesAndPubKeyAlgs);
    if (supportedAlgorithm === undefined) {
        throw new NotSupportedError('Given credential type or algorithm is not supported');
    }

    // Step 3
    if (excludeCredentialDescriptorList !== undefined) {
        for (const descriptor of excludeCredentialDescriptorList) {
            const credential = await lookupCredentialById(descriptor.id);
            if (credential !== null && credential.rpId === rpEntity.id && credential.type === descriptor.type) {
                const userConsented = await askUserForDisclosureConsent(credential);
                if (userConsented) {
                    throw new InvalidStateError('User consented to disclosure of excluded credential');
                } else {
                    throw new NotAllowedError('User did not consent to disclosure of excluded credential');
                }
            }
        }
    }

    // Step 4
    if (requireResidentKey && !AUTHENTICATOR_CAPABILITIES.supportsResidentKeys) {
        throw new ConstraintError('Resident keys are not supported');
    }

    // Step 5
    if (requireUserVerification && !AUTHENTICATOR_CAPABILITIES.supportsUserVerification) {
        throw new ConstraintError('User verification is not supported');
    }

    // Step 6
    const { userConsented, userVerified } = await askUserForCreationConsent(rpEntity, userEntity, requireUserVerification);
    if (!userConsented) {
        throw new NotAllowedError('User did not consent to credential creation');
    }

    let credentialSource: PublicKeyCredentialSource;
    let publicKey: CryptoKey;
    let privateKey: JsonWebKey;
    try {
        // Step 7.1
        const keyGenParams = getKeyGenParams(supportedAlgorithm);
        const keyPair = await crypto.subtle.generateKey(keyGenParams, true, ['sign', 'verify']);
        publicKey = keyPair.publicKey;
        privateKey = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

        // Step 7.2
        const userHandle = getArrayBuffer(userEntity.id);

        // Step 7.3
        const partialCredentialSource: Omit<PublicKeyCredentialSource, 'id'> = {
            type: 'public-key',
            privateKey,
            rpId: rpEntity.id,
            userHandle,
            otherUI: {
                username: userEntity.name,
                // Step 10
                signatureCounter: 0
            }
        };

        if (requireResidentKey) {
            // Step 7.4.1
            const credentialId = getRandomBytes(16).buffer;

            // Step 7.4.2
            credentialSource = {
                ...partialCredentialSource,
                id: credentialId,
            };

            // Step 7.4.3 and 7.4.4
            await storeCredential(credentialSource);
        } else {
            // Step 7.5
            credentialSource = {
                ...partialCredentialSource,
                id: await encryptCredential(partialCredentialSource)
            }

            // Step 10
            // Store the signature counter and username.
            await storeCredentialOtherUI(credentialSource.id, credentialSource.otherUI);
        }
    } catch (err) {
        console.error('Caught error while creating credential', err);
        // Step 8
        throw new UnknownError('Error occurred while creating credential');
    }

    // Step 9
    // No authenticator extensions are supported.
    const processedExtensions = {};

    // Step 10 was already done above when creating the credential.

    // Step 11
    const attestedCredentialData = await generateAttestedCredentialData(credentialSource.id, publicKey);

    // Step 12
    const rpIdHash = await createHash(rpEntity.id);
    const flags = generateFlags(userVerified, true, Object.keys(processedExtensions).length > 0);
    const authenticatorData = generateAuthenticatorData(rpIdHash, flags, credentialSource.otherUI.signatureCounter, attestedCredentialData, processedExtensions);

    // Step 13
    const attestationObject = await generateAttestationObject(privateKey, authenticatorData, hash, enterpriseAttestationPossible);

    return attestationObject;
}

export async function authenticatorGetAssertion(
    rpId: string,
    hash: ArrayBuffer,
    requireUserVerification: boolean,
    extensions: Map<unknown, unknown>,
    allowCredentialDescriptorList?: PublicKeyCredentialDescriptor[]
): Promise<AuthenticatorAssertion> {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion
    console.log('Called authenticatorGetAssertion');

    // Step 1
    // Because there's been no serialisation and deserialisation, hash is the only thing that could be malformed.
    if (hash.byteLength !== 32) {
        throw new UnknownError('Hash length is invalid');
    }

    // Step 2
    // Using an array instead of a set because sets of objects aren't useful.
    let credentialOptions: PublicKeyCredentialSource[] = []

    if (allowCredentialDescriptorList !== undefined) {
        // Step 3
        for (const descriptor of allowCredentialDescriptorList) {
            const credential = await lookupCredentialById(descriptor.id);
            if (credential !== null) {
                credentialOptions.push(credential);
            }
        }
    } else {
        // Step 4
        const credentials = await getAllStoredCredentials();
        credentialOptions.push(...credentials);
    }

    // Step 5
    credentialOptions = credentialOptions.filter(c => c.rpId === rpId);

    // Step 6
    if (credentialOptions.length === 0) {
        throw new NotAllowedError('No matching credentials');
    }

    // Step 7
    const { selectedCredential, userVerified } = await askUserForSelection(credentialOptions, rpId, requireUserVerification);
    if (selectedCredential === undefined) {
        throw new NotAllowedError('User did not consent to credential use');
    }

    // Step 8
    // No extensions are supported.
    const processedExtensions = {};

    // Step 9
    await incrementSignatureCounter(selectedCredential);

    // Step 10
    const rpIdHash = await createHash(rpId);
    const flags = generateFlags(userVerified, false, Object.keys(processedExtensions).length > 0);
    const authenticatorData = generateAuthenticatorData(rpIdHash, flags, selectedCredential.otherUI.signatureCounter, undefined, processedExtensions);

    // Step 11
    let signature: ArrayBuffer;
    try {
        signature = await generateSignature(selectedCredential.privateKey, authenticatorData, hash);
    } catch (err) {
        console.error('Caught error while generating signature', err);
        // Step 12
        throw new UnknownError('Error occurred while generating signature');
    }

    // Step 13
    const credentialId = allowCredentialDescriptorList === undefined
            || allowCredentialDescriptorList.length > 1
        ? selectedCredential.id
        : undefined;
    return {
        credentialId,
        authenticatorData: authenticatorData.buffer,
        signature,
        userHandle: selectedCredential.userHandle
    };
}

export async function authenticatorCancel() {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-cancel
    console.log('Called authenticatorCancel');
    // TODO: Implement this. Probably need some sort of request ID to store and then match against before persisting or returning any data in the other authenticator interface functions.
}
