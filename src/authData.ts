import { getImportAlgorithm } from "./algorithm";
import { assert } from "./assert";
import { CBOR_TYPE_BYTE_STRING } from "./cbor/common";
import { parseCBOR } from "./cbor/decode";
import { coseToJwk, jwkAlgToCoseIdentifier } from "./cose";

const FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED = 0b0100_0000;
const FLAGS_OFFSET = 32;
const AAGUID_OFFSET = 37;
const AAGUID_LENGTH = 16;

function isBitFlagSet(flags: number, flag: number) {
    return (flags & flag) === flag;
};

function assertAttestedCredentialDataIsPresent(authData: Uint8Array) {
    const flags = authData[FLAGS_OFFSET];
    assert(flags !== undefined);
    assert(isBitFlagSet(flags, FLAG_ATTESTED_CREDENTIAL_DATA_INCLUDED), 'Attested credential data is not included in attestation object auth data');
};

function isZeroes(typedArray: Uint8Array) {
    return typedArray.every(b => b === 0);
};

function setAaguidToZero(authData: Uint8Array) {
    assertAttestedCredentialDataIsPresent(authData);

    for (let i = AAGUID_OFFSET; i < AAGUID_OFFSET + AAGUID_LENGTH; i += 1) {
        authData[i] = 0;
    }

    return authData;
};

function encodeWithAttestationTypeNone(authData: Uint8Array) {
    const authDataPrefixBytes = [
        (CBOR_TYPE_BYTE_STRING << 5)
    ];

    if (authData.byteLength < 24) {
        authDataPrefixBytes[0] |= authData.byteLength;
    } else if (authData.byteLength <= 0xFF) {
        authDataPrefixBytes[0] |= 24;
        authDataPrefixBytes.push(authData.byteLength);
    } else if (authData.byteLength <= 0xFFFF) {
        authDataPrefixBytes[0] |= 25;
        authDataPrefixBytes.push((authData.byteLength & 0xFF00) >> 8);
        authDataPrefixBytes.push(authData.byteLength & 0x00FF);
    } else if (authData.byteLength <= 0xFFFF_FFFF) {
        console.warn('Auth data seems a bit long: ', authData.byteLength);
        authDataPrefixBytes[0] |= 26;
        authDataPrefixBytes.push((authData.byteLength & 0xFF00_0000) >> 24);
        authDataPrefixBytes.push((authData.byteLength & 0x00FF_0000) >> 16);
        authDataPrefixBytes.push((authData.byteLength & 0x0000_FF00) >> 8);
        authDataPrefixBytes.push(authData.byteLength & 0x0000_00FF);
    } else {
        throw new Error('Why is the auth data more than 4 GB long?');
    }

    // To save having to write a CBOR encoder, just hardcode the bytes needed.
    const prefix = [
        // A map with 3 entries
        0xa3,
        // fmt: "none"
        0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65,
        // attStmt: {}
        0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74, 0xa0,
        // authData key
        0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61,
        // Need to also add the type and size for authData. The type is
        ...authDataPrefixBytes
    ];

    const complete = new Uint8Array(prefix.length + authData.byteLength);
    complete.set(prefix);
    complete.set(authData, prefix.length);


    return complete;
};

async function encodeAsSpki(jwk: JsonWebKey) {
    // Easiest way to encode a COSE key as SPKI is to convert it to JWK first, then import it using importKey() and then use exportKey() to export it as SPKI.
    const key = await crypto.subtle.importKey('jwk', jwk, getImportAlgorithm(jwk), true, ['verify']);

    return crypto.subtle.exportKey('spki', key);
}

export async function parseAuthData(authData: Uint8Array) {
    assertAttestedCredentialDataIsPresent(authData);

    const aaguid = authData.slice(AAGUID_OFFSET, AAGUID_OFFSET + AAGUID_LENGTH);

    const CREDENTIAL_ID_LENGTH_OFFSET = AAGUID_OFFSET + AAGUID_LENGTH;
    // Stored as a big-endian uint16
    const credentialIdLength = (authData[CREDENTIAL_ID_LENGTH_OFFSET]! << 8) | authData[CREDENTIAL_ID_LENGTH_OFFSET + 1]!;

    const CREDENTIAL_ID_OFFSET = CREDENTIAL_ID_LENGTH_OFFSET + 2;
    const credentialId = authData.slice(CREDENTIAL_ID_OFFSET, CREDENTIAL_ID_OFFSET + credentialIdLength);

    const [publicKey,] = parseCBOR(authData.slice(CREDENTIAL_ID_OFFSET + credentialIdLength));
    assert(publicKey instanceof Map, "Parsed CBOR public key should be a Map");

    const jwk = coseToJwk(publicKey);
    const spkiPublicKey = await encodeAsSpki(jwk);
    const publicKeyAlgorithm = jwkAlgToCoseIdentifier(jwk.alg);

    return { aaguid, credentialId, publicKey: spkiPublicKey, publicKeyAlgorithm };
}

export function isSelfAttestationUsed(fmt: string, attStmt: Map<unknown, unknown>, aaguid: Uint8Array) {
    return isZeroes(aaguid) && fmt === 'packed' && attStmt.has('x5c');
}

export function replaceIdentifyingInfo(authData: Uint8Array): ArrayBuffer {
    setAaguidToZero(authData);
    return encodeWithAttestationTypeNone(authData);
}
