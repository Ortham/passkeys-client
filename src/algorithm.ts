import { COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_ALG_ES384, COSE_ALG_ES512, COSE_ALG_PS256, COSE_ALG_RS256, JWK_ALG_EDDSA, JWK_ALG_ES256, JWK_ALG_ES384, JWK_ALG_ES512, JWK_ALG_PS256, JWK_ALG_RS256 } from "./cose";


export function getSigningAlgorithm(jwk: JsonWebKey): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
    switch(jwk.alg) {
        case JWK_ALG_EDDSA:
            return { name: 'Ed25519' };
        case JWK_ALG_ES256:
            return { name: 'ECDSA', hash: 'SHA-256' };
        case JWK_ALG_ES384:
            return { name: 'ECDSA', hash: 'SHA-384' };
        case JWK_ALG_ES512:
            return { name: 'ECDSA', hash: 'SHA-512' };
        case JWK_ALG_PS256:
            return { name: 'RSA-PSS', saltLength: 32 };
        case JWK_ALG_RS256:
            return { name: 'RSASSA-PKCS1-v1_5' };
        default:
            throw new Error('Unrecognised algorithm ' + jwk.alg);
    }
}

export function getImportAlgorithm(jwk: JsonWebKey): RsaHashedImportParams | EcKeyImportParams | Algorithm  {
    switch(jwk.alg) {
        case JWK_ALG_EDDSA:
            return { name: 'Ed25519' };
        case JWK_ALG_ES256:
            return { name: 'ECDSA', namedCurve: 'P-256' };
        case JWK_ALG_ES384:
            return { name: 'ECDSA', namedCurve: 'P-384' };
        case JWK_ALG_ES512:
            return { name: 'ECDSA', namedCurve: 'P-521' };
        case JWK_ALG_PS256:
            return { name: 'RSA-PSS', hash: 'SHA-256' };
        case JWK_ALG_RS256:
            return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
        default:
            throw new Error('Unrecognised algorithm ' + jwk.alg);
    }
}

export function getKeyGenParams(algorithm: COSEAlgorithmIdentifier): RsaHashedKeyGenParams | EcKeyGenParams {
    switch(algorithm) {
        case COSE_ALG_EDDSA:
            // The type cast here is needed as returning an Algorithm messes up type inference later, as it then appears that generateKey() could return a symmetric key instead of a key pair.
            return { name: 'Ed25519' } as EcKeyGenParams;
        case COSE_ALG_ES256:
            return { name: 'ECDSA', namedCurve: 'P-256' };
        case COSE_ALG_ES384:
            return { name: 'ECDSA', namedCurve: 'P-384' };
        case COSE_ALG_ES512:
            return { name: 'ECDSA', namedCurve: 'P-521' };
        case COSE_ALG_PS256:
            return {
                name: 'RSA-PSS',
                modulusLength: 4096,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: 'SHA-256'
            };
        case COSE_ALG_RS256:
            return {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: 4096,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: 'SHA-256'
            };
        default:
            throw new Error('Unrecognised algorithm ' + algorithm);
    }
}

export function isSupportedAlgorithm(algorithm: COSEAlgorithmIdentifier): boolean {
    return algorithm === COSE_ALG_EDDSA
        || algorithm === COSE_ALG_ES256
        || algorithm === COSE_ALG_ES384
        || algorithm === COSE_ALG_ES512
        || algorithm === COSE_ALG_PS256
        || algorithm === COSE_ALG_RS256;
}
