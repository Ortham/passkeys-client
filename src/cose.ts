import { assert } from "./assert.js";
import { DecodedValue } from "./cbor/decode.js";
import { fromBase64Url, toBase64Url } from "./util.js";

export const COSE_ALG_ES256 = -7;
const COSE_ALG_EDDSA = -8;
export const COSE_ALG_RS256 = -257;
const COSE_EC_P256 = 1;
const COSE_EC_ED25519 = 6;
const COSE_KEY_TYPE_EC2 = 2;
const COSE_KEY_TYPE_OKP = 1;
const COSE_KEY_TYPE_RSA = 3;

export interface CoseKey {
    '1': number;
    '3': number;

    [key: string]: unknown;
}

interface EcdsaCoseKey extends CoseKey {
    '1': typeof COSE_KEY_TYPE_EC2;
    '3': typeof COSE_ALG_ES256;
    '-1': typeof COSE_EC_P256;
    '-2': Uint8Array;
    '-3': Uint8Array;
}

interface EddsaCoseKey extends CoseKey {
    '1': typeof COSE_KEY_TYPE_OKP;
    '3': typeof COSE_ALG_EDDSA;
    '-1': typeof COSE_EC_ED25519;
    '-2': Uint8Array;
}

interface RsaCoseKey extends CoseKey {
    '1': typeof COSE_KEY_TYPE_RSA;
    '3': typeof COSE_ALG_RS256;
    '-1': Uint8Array;
    '-2': Uint8Array;
}

function isEcdsaCoseKey(key: CoseKey): key is EcdsaCoseKey {
    return key['1'] === COSE_KEY_TYPE_EC2
        && key['3'] === COSE_ALG_ES256
        && key['-1'] === COSE_EC_P256
        && key['-2'] instanceof Uint8Array
        && key['-3'] instanceof Uint8Array;
}

function isEddsaCoseKey(key: CoseKey): key is EddsaCoseKey {
    return key['1'] === COSE_KEY_TYPE_OKP
        && key['3'] === COSE_ALG_EDDSA
        && key['-1'] === COSE_EC_ED25519
        && key['-2'] instanceof Uint8Array;
}

function isRsaCoseKey(key: CoseKey): key is RsaCoseKey {
    return key['1'] === COSE_KEY_TYPE_RSA
        && key['3'] === COSE_ALG_RS256
        && key['-1'] instanceof Uint8Array
        && key['-2'] instanceof Uint8Array;
}

function ecdsaCoseToJwk(key: EcdsaCoseKey): JsonWebKey {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518

    return {
        kty: 'EC',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'ES256',
        crv: 'P-256',
        x: toBase64Url(key['-2']),
        y: toBase64Url(key['-3'])
    };
}

function eddsaCoseToJwk(key: EddsaCoseKey): JsonWebKey {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518

    return {
        kty: 'OKP',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'EdDSA',
        crv: 'Ed25519',
        x: toBase64Url(key['-2'])
    };
}

function rsaCoseToJwk(key: RsaCoseKey): JsonWebKey {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518

    return {
        kty: 'RSA',
        use: 'sig',
        key_ops: ['verify'],
        alg: 'RS256',
        n: toBase64Url(key['-1']),
        e: toBase64Url(key['-2'])
    };
}

export function mapToCoseKey(map: Map<DecodedValue, DecodedValue>): CoseKey {
    const publicKey = Object.fromEntries(map);

    assert(publicKey !== null, 'The public key is null');
    assert(typeof publicKey === 'object', 'The public key is not an object');
    assert('1' in publicKey, 'The public key\'s kty field is missing');
    assert('3' in publicKey, 'The public key\'s alg field is missing');

    return publicKey;
}

export function coseToJwk(key: CoseKey): JsonWebKey {
    // https://www.iana.org/assignments/cose/cose.xhtml#key-type

    if (isEcdsaCoseKey(key)) {
        return ecdsaCoseToJwk(key);
    }

    if (isEddsaCoseKey(key)) {
        return eddsaCoseToJwk(key);
    }

    if (isRsaCoseKey(key)) {
        return rsaCoseToJwk(key);
    }

    throw new Error('Unexpected key type ' + key['1']);
}

export function jwkToCose(jwk: JsonWebKey): CoseKey {
    if (jwk.alg === 'ES256') {
        assert(jwk.crv === 'P-256');
        assert(jwk.x !== undefined);
        assert(jwk.y !== undefined);

        return {
            '1': COSE_KEY_TYPE_EC2,
            '3': COSE_ALG_ES256,
            '-1': COSE_EC_P256,
            '-2': fromBase64Url(jwk.x),
            '-3': fromBase64Url(jwk.y),
        }
    }

    if (jwk.alg === 'EdDSA') {
        assert(jwk.crv === 'Ed25519');
        assert(jwk.x !== undefined);

        return {
            '1': COSE_KEY_TYPE_EC2,
            '3': COSE_ALG_ES256,
            '-1': COSE_EC_P256,
            '-2': fromBase64Url(jwk.x),
        }
    }

    if (jwk.alg === 'RS256') {
        assert(jwk.n !== undefined);
        assert(jwk.e !== undefined);

        return {
            '1': COSE_KEY_TYPE_RSA,
            '3': COSE_ALG_RS256,
            '-1': fromBase64Url(jwk.n),
            '-2': fromBase64Url(jwk.e),
        }
    }

    throw new Error('Unexpected key algorithm ' + jwk.alg);
}
