import { assert } from "../assert";
import { getCredentialHmacSecretData, storeCredentialHmacSecretData } from "../background/store";
import { decodeByteString, decodeFloat, parseCBOR } from "../cbor/decode";
import { concatArrays, encodeArrayBuffer, encodeBoolean, encodeMap } from "../cbor/encode";
import { fromBase64Url, getArrayBuffer, getRandomBytes, toBase64Url } from "../util";

// https://www.w3.org/TR/webauthn-3/#prf-extension
export const EXTENSION_ID_PRF = 'prf';

type AuthenticationExtensionsPRFValues = {
    first: BufferSource;
    second?: BufferSource;
};

export type AuthenticationExtensionsPRFInputs = {
    eval?: AuthenticationExtensionsPRFValues;
    evalByCredential?: Map<string, AuthenticationExtensionsPRFValues>;
};

export type AuthenticationExtensionsPRFOutputs = {
    enabled?: boolean;
    results?: AuthenticationExtensionsPRFValues;
};

type AuthenticatorExtensionEntry = {
    authenticatorExtensionId: string;
    authenticatorExtensionInput: ArrayBuffer;
};

async function generateSalt(input: BufferSource): Promise<ArrayBuffer> {
    const data = concatArrays(
        new TextEncoder().encode('WebAuthn PRF'),
        new Uint8Array([0]),
        new Uint8Array(getArrayBuffer(input))
    );

    return crypto.subtle.digest('SHA-256', data);
}

export function prfProcessRegistrationInput(input: AuthenticationExtensionsPRFInputs): AuthenticatorExtensionEntry {
    // Registration Step 1
    if (input.evalByCredential !== undefined) {
        throw new DOMException('evalByCredential is not supported during registration', 'NotSupportedError');
    }

    // Registration Step 2
    return {
        authenticatorExtensionId: 'hmac-secret',
        authenticatorExtensionInput: encodeBoolean(true)
    };

    // Registration Step 3 skipped - no extension to FIDO-CTAP currently permits evaluation of the PRF at creation time.
}

export function prfProcessRegistrationOutput(authenticatorExtensionsOutput: Map<string, Uint8Array>): { enabled: boolean; } {
    // Registration Step 4
    const output = authenticatorExtensionsOutput.get('hmac-secret');
    if (output === undefined) {
        return {
            enabled: false
        };
    }

    const enabled = decodeFloat(output).value;
    assert(typeof enabled === 'boolean');

    return { enabled };

    // Registration Step 5 skipped - no extension to FIDO-CTAP currently permits evaluation of the PRF at creation time.
}

export async function prfProcessAuthenticationInput(input: AuthenticationExtensionsPRFInputs, allowCredentials?: PublicKeyCredentialDescriptor[]): Promise<AuthenticatorExtensionEntry | {}> {
    // Authentication Step 1
    if (input.evalByCredential !== undefined
        && (allowCredentials === undefined || allowCredentials.length === 0)) {
        throw new DOMException('evalByCredential cannot be used with no allowed credentials', 'NotSupportedError');
    }

    // Authentication Step 2
    const credentialIds = new Set((allowCredentials ?? []).map(c => toBase64Url(c.id)));
    if (input.evalByCredential !== undefined) {
        for (const [key,] of input.evalByCredential) {
            if (key.length === 0 || !credentialIds.has(key)) {
                throw new DOMException('Invalid credential ID given in evalByCredential', 'SyntaxError');
            }
        }
    }

    // Step 3
    const output: Partial<AuthenticatorExtensionEntry> = {};

    // Step 4
    let ev = null;
    if (input.evalByCredential !== undefined) {
        if (credentialIds.size === 1) {
            const credentialId = credentialIds.keys().next().value;
            ev = input.evalByCredential.get(credentialId);
        }
        // TODO: I don't understand this bit, how do I know which credential ID will be returned at this point if there are multiple allowed credentials? I need to know to create input for authenticatorGetAssertion, but if there are multiple allowed credential then the user only picks one to use halfway through authenticatorGetAssertion.
    }

    if (ev === null && input.eval !== undefined) {
        ev = input.eval;
    }

    // Step 5
    if (ev !== null && ev !== undefined) {

        const salt1 = await generateSalt(ev.first);
        const salt2 = ev.second === undefined ? undefined : await generateSalt(ev.second);

        assert(salt1.byteLength === 32);
        assert(salt2 === undefined || salt2.byteLength === 32);

        const salt = salt2 === undefined
            ? salt1
            : concatArrays(new Uint8Array(salt1), new Uint8Array(salt2)).buffer;

        // FIXME: This is not a spec-compliant hmac-secret implementation, because that involves different input parameters and encryption and signing using a secret shared between the authenticator and client, which involves use of an authenticator-specific key pair and a bunch of FIDO-specific functionality. None of it is necessary to get the same behaviour from an RP's perspective.

        output['authenticatorExtensionId'] = 'hmac-secret';
        output['authenticatorExtensionInput'] = encodeMap(new Map([
            ['salt', salt]
        ]));
    }

    return output;
}

export function prfProcessAuthenticationOutput(authenticatorExtensionsOutput: Map<string, Uint8Array>): { results?: AuthenticationExtensionsPRFValues; } {
    // Authentication Step 4
    const output = authenticatorExtensionsOutput.get('hmac-secret');
    if (output === undefined) {
        return {};
    }

    // FIXME: Decrypt the extension result
    const byteArray = decodeByteString(output).value;

    if (byteArray.byteLength === 64) {
        return {
            results: {
                first: byteArray.subarray(0, 32),
                second: byteArray.subarray(32)
            }
        };
    }

    return {
        results: {
            first: byteArray
        }
    };
}

export async function hmacSecretProcessMakeCredential(extensionInput: string, credentialId: ArrayBuffer): Promise<Uint8Array | undefined> {
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension
    const value = parseCBOR(new Uint8Array(fromBase64Url(extensionInput)));
    assert(value.length === 1);
    assert(typeof value[0] === 'boolean');
    if (!value[0]) {
        return undefined;
    }

    try {
        const data = {
            credRandomWithUV: getRandomBytes(32),
            credRandomWithoutUV: getRandomBytes(32)
        }

        await storeCredentialHmacSecretData(credentialId, data);

        return encodeBoolean(true);
    } catch (err) {
        console.log('Failed to associate hmac-secret data with credential', err);
        return encodeBoolean(false);
    }
}

export async function hmacSecretProcessGetAssertion(extensionInput: string, credentialId: ArrayBuffer) {
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension
    // Deviating from the specified additional behaviours because a lot of the steps are already taken care of as part of WebAuthn's procedures, e.g. tt this point the relevant WebAuthn user presence or user verification check has been completed.

    const value = parseCBOR(new Uint8Array(fromBase64Url(extensionInput)));
    assert(value.length === 1);
    assert(value[0] instanceof Map);

    // FIXME: This salt should need decrypting and have a signature that would need verification.
    const salt = value[0].get('salt');
    assert(salt instanceof Uint8Array);

    let salt1;
    let salt2;
    if (salt.byteLength === 64) {
        salt1 = salt.subarray(0, 32);
        salt2 = salt.subarray(32);
    } else {
        salt1 = salt;
    }

    assert(salt2 === undefined || salt2 instanceof Uint8Array);

    const data = await getCredentialHmacSecretData(credentialId);

    if (data === null) {
        return undefined;
    }

    // The PRF "MUST be the one used for when user verification is performed".
    const credRandom = data.credRandomWithUV;

    const key = await crypto.subtle.importKey('raw', credRandom, { name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);
    const output1 = await crypto.subtle.sign({ name: 'HMAC' }, key, salt1);
    const output2 = salt2 === undefined
        ? undefined
        : await crypto.subtle.sign({ name: 'HMAC' }, key, salt2);

    // FIXME: The returned array buffer should first be encrypted using a shared secret.
    if (output2 === undefined) {
        return encodeArrayBuffer(output1);
    } else {
        return encodeArrayBuffer(concatArrays(new Uint8Array(output1), new Uint8Array(output2)));
    }
}
