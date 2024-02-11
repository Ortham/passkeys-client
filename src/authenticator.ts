export type CredTypesAndPubKeyAlg = {
    type: PublicKeyCredentialType;
    alg: COSEAlgorithmIdentifier;
};

export function lookupCredentialById(
credentialId: ArrayBuffer
) {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-lookup-credsource-by-credid
    console.log('Called lookupCredentialById');
}

export function authenticatorMakeCredential(
    hash: Uint8Array,
    rpEntity: PublicKeyCredentialRpEntity,
    userEntity: PublicKeyCredentialUserEntity,
    requireResidentKey: boolean,
    requireUserVerification: boolean,
    credTypesAndPubKeyAlgs: CredTypesAndPubKeyAlg[],
    enterpriseAttestationPossible: boolean,
    extensions: Map<unknown, unknown>,
    excludeCredentialDescriptorList?: PublicKeyCredentialDescriptor[],
) {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-make-cred
    console.log('Called authenticatorMakeCredential');
}

export function authenticatorGetAssertion(
    rpId: string,
    hash: Uint8Array,
    requireUserVerification: boolean,
    extensions: Map<unknown, unknown>,
    allowCredentialDescriptorList?: PublicKeyCredentialDescriptor[]
) {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-get-assertion
    console.log('Called authenticatorGetAssertion');

}

export function authenticatorCancel() {
    // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-cancel
    console.log('Called authenticatorCancel');
}
