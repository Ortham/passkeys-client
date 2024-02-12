// Types that are shared across background, content and page scripts.

export type CredTypeAndPubKeyAlg = {
    type: PublicKeyCredentialType;
    alg: COSEAlgorithmIdentifier;
}

export type AuthenticatorAssertion = {
    credentialId: ArrayBuffer | undefined;
    authenticatorData: ArrayBuffer;
    signature: ArrayBuffer;
    userHandle: ArrayBuffer | null;
};
