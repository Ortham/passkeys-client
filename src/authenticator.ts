export type CredTypesAndPubKeyAlg = {
    type: PublicKeyCredentialType;
    alg: COSEAlgorithmIdentifier;
};

export type AuthenticatorAssertion = {
    credentialId: ArrayBuffer;
    authenticatorData: ArrayBuffer;
    signature: ArrayBuffer;
    userHandle: ArrayBuffer | null;
}

export class UserCancelledError extends Error {

}

export class InvalidStateError extends Error {

}

export async function lookupCredentialById(
    rpId: string,
    allowedCredentialIds: BufferSource[]
): Promise<PublicKeyCredentialDescriptor[]> {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-lookup-credsource-by-credid
    console.log('Called lookupCredentialById');
    return [];
}

export async function authenticatorMakeCredential(
    hash: ArrayBuffer,
    rpEntity: PublicKeyCredentialRpEntity,
    userEntity: PublicKeyCredentialUserEntity,
    requireResidentKey: boolean,
    requireUserVerification: boolean,
    credTypesAndPubKeyAlgs: CredTypesAndPubKeyAlg[],
    enterpriseAttestationPossible: boolean,
    extensions: Map<unknown, unknown>,
    excludeCredentialDescriptorList?: PublicKeyCredentialDescriptor[],
): Promise<ArrayBuffer> {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-make-cred
    console.log('Called authenticatorMakeCredential');
    return new ArrayBuffer(0);
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

    return {
        credentialId: new ArrayBuffer(0),
        authenticatorData: new ArrayBuffer(0),
        signature: new ArrayBuffer(0),
        userHandle: null
    };
}

export async function authenticatorCancel() {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-cancel
    console.log('Called authenticatorCancel');
}
