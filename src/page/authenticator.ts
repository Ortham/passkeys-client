import { AuthenticatorAssertion, CredTypeAndPubKeyAlg } from "../types";
import { MESSAGE_TARGET_CONTENT_SCRIPT, MESSAGE_TARGET_PAGE_SCRIPT, getRandomBytes, toBase64Url } from "../util";

export class UserCancelledError extends Error {}

export class InvalidStateError extends Error {}

function sendMessage<T>(invoke: string, parameters: Record<string, unknown>): Promise<T> {
    return new Promise((resolve, reject) => {
        const messageId = toBase64Url(getRandomBytes(16));

        const listener = (event: any) => {
            if (event.data?.messageId === messageId
                && event.data?.target === MESSAGE_TARGET_PAGE_SCRIPT) {
                console.log('Received result event in page script', event);
                window.removeEventListener('message', listener);

                if (event.data.result instanceof Error) {
                    reject(event.data.result);
                } else {
                    resolve(event.data.result);
                }
            }
        };
        window.addEventListener('message', listener);

        window.postMessage({
            messageId,
            target: MESSAGE_TARGET_CONTENT_SCRIPT,
            invoke,
            parameters
        }, window.origin);
    });
}

export async function lookupCredentialsById(
    rpId: string,
    allowedCredentialIds: BufferSource[]
): Promise<PublicKeyCredentialDescriptor[]> {
    return sendMessage<PublicKeyCredentialDescriptor[]>('lookupCredentialsById', {
        rpId,
        allowedCredentialIds
    });
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
    return sendMessage<ArrayBuffer>('authenticatorMakeCredential', {
        hash,
        rpEntity,
        userEntity,
        requireResidentKey,
        requireUserVerification,
        credTypesAndPubKeyAlgs,
        enterpriseAttestationPossible,
        extensions,
        excludeCredentialDescriptorList
    });
}

export async function authenticatorGetAssertion(
    rpId: string,
    hash: ArrayBuffer,
    requireUserVerification: boolean,
    extensions: Map<unknown, unknown>,
    allowCredentialDescriptorList?: PublicKeyCredentialDescriptor[]
): Promise<AuthenticatorAssertion> {
    return sendMessage<AuthenticatorAssertion>('authenticatorGetAssertion', {
        rpId,
        hash,
        requireUserVerification,
        extensions,
        allowCredentialDescriptorList
    });
}

export async function authenticatorCancel() {
    return sendMessage<void>('authenticatorCancel', {});
}
