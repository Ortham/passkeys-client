import { authenticatorCancel, authenticatorGetAssertion, authenticatorMakeCredential, lookupCredentialsById } from "./authenticator";

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Received message in background script', message, 'from', sender);

    let promise;
    if (message.invoke === 'lookupCredentialsById') {
        promise = lookupCredentialsById(message.parameters.rpId,
            message.parameters.allowedCredentialIds);
    } else if (message.invoke === 'authenticatorMakeCredential') {
        promise = authenticatorMakeCredential(message.parameters.hash,
            message.parameters.rpEntity,
            message.parameters.userEntity,
            message.parameters.requireResidentKey,
            message.parameters.requireUserVerification,
            message.parameters.credTypesAndPubKeyAlgs,
            message.parameters.enterpriseAttestationPossible,
            message.parameters.extensions,
            message.parameters.excludeCredentialDescriptorList);
    } else if (message.invoke === 'authenticatorGetAssertion') {
        promise = authenticatorGetAssertion(message.parameters.rpId,
            message.parameters.hash,
            message.parameters.requireUserVerification,
            message.parameters.extensions,
            message.parameters.allowCredentialDescriptorList);
    } else if (message.invoke === 'authenticatorCancel') {
        promise = authenticatorCancel();
    }

    if (promise !== undefined) {
        promise.then(sendResponse, sendResponse);
        return true;
    }

    return false;
});
