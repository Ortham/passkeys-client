import { assert, strictEqual } from "./assert.js";
import { fromBase64Url, toBase64Url } from "./util.js";

export const COSE_ALG_ES256 = -7;
const COSE_ALG_EDDSA = -8;
export const COSE_ALG_RS256 = -257;
const COSE_EC_P256 = 1;
const COSE_EC_ED25519 = 6;
const COSE_KEY_TYPE_OKP = 1;
const COSE_KEY_TYPE_EC2 = 2;
const COSE_KEY_TYPE_RSA = 3;

export function coseToJwk(coseKey: Map<unknown, unknown>): JsonWebKey {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518

    const kty = coseKey.get(1);
    const alg = coseKey.get(3);

    if (alg === COSE_ALG_EDDSA) {
        strictEqual(kty, COSE_KEY_TYPE_OKP);
        strictEqual(coseKey.get(-1), COSE_EC_ED25519);

        const x = coseKey.get(-2);
        assert(x instanceof Uint8Array);

        return {
            kty: 'OKP',
            use: 'sig',
            key_ops: ['verify'],
            alg: 'EdDSA',
            crv: 'Ed25519',
            x: toBase64Url(x)
        };
    } else if (alg === COSE_ALG_ES256) {
        strictEqual(kty, COSE_KEY_TYPE_EC2);
        strictEqual(coseKey.get(-1), COSE_EC_P256);

        const x = coseKey.get(-2);
        const y = coseKey.get(-3);

        assert(x instanceof Uint8Array);
        assert(y instanceof Uint8Array);

        return {
            kty: 'EC',
            use: 'sig',
            key_ops: ['verify'],
            alg: 'ES256',
            crv: 'P-256',
            x: toBase64Url(x),
            y: toBase64Url(y)
        };
    } else if (alg === COSE_ALG_RS256) {
        strictEqual(kty, COSE_KEY_TYPE_RSA);

        const n = coseKey.get(-1);
        const e = coseKey.get(-2);

        assert(n instanceof Uint8Array);
        assert(e instanceof Uint8Array);

        return {
            kty: 'RSA',
            use: 'sig',
            key_ops: ['verify'],
            alg: 'RS256',
            n: toBase64Url(n),
            e: toBase64Url(e)
        };
    } else {
        throw new Error('Unexpected key algorithm ' + alg);
    }
}

export function jwkToCose(jwk: JsonWebKey): Map<number, unknown> {
    // https://www.iana.org/assignments/cose/cose.xhtml
    // https://datatracker.ietf.org/doc/html/rfc7518

    let entries: [number, unknown][];

    if (jwk.alg === 'EdDSA') {
        assert(jwk.crv === 'Ed25519');
        assert(jwk.x !== undefined);

        entries = [
            [1, COSE_KEY_TYPE_OKP],
            [3, COSE_ALG_EDDSA],
            [-1, COSE_EC_ED25519],
            [-2, fromBase64Url(jwk.x)],
        ];
    } else if (jwk.alg === 'ES256') {
        assert(jwk.crv === 'P-256');
        assert(jwk.x !== undefined);
        assert(jwk.y !== undefined);

        entries = [
            [1, COSE_KEY_TYPE_EC2],
            [3, COSE_ALG_ES256],
            [-1, COSE_EC_P256],
            [-2, fromBase64Url(jwk.x)],
            [-3, fromBase64Url(jwk.y)]
        ];
    } else if (jwk.alg === 'RS256') {
        assert(jwk.n !== undefined);
        assert(jwk.e !== undefined);

        entries = [
            [1, COSE_KEY_TYPE_RSA],
            [3, COSE_ALG_RS256],
            [-1, fromBase64Url(jwk.n)],
            [-2, fromBase64Url(jwk.e)],
        ];
    } else {
        throw new Error('Unexpected key algorithm ' + jwk.alg);
    }

    return new Map(entries);
}

export function jwkAlgToCoseIdentifier(alg: string | undefined): COSEAlgorithmIdentifier {
    if (alg === 'ES256') {
        return COSE_ALG_ES256;
    }

    if (alg === 'EdDSA') {
        return COSE_ALG_EDDSA;
    }

    if (alg === 'RS256') {
        return COSE_ALG_RS256;
    }

    throw new Error('Unexpected key algorithm ' + alg);
}
