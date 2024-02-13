import { MESSAGE_TARGET_BACKGROUND_SCRIPT } from "../util";
import { authenticatorCancel, authenticatorGetAssertion, authenticatorMakeCredential, lookupCredentialsById } from "./authenticator";
import { askUserToCreatePassword } from "./user";

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.target !== MESSAGE_TARGET_BACKGROUND_SCRIPT) {
        return;
    }

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

const PASSWORD_KEY = 'user_password';

async function isPasswordStored() {
    console.log('Checking if password is stored');
    const results = await browser.storage.local.get({ [PASSWORD_KEY]: null });

    return !!results[PASSWORD_KEY];
}

async function initialisePassword() {
    const isStored = await isPasswordStored();
    console.log('Password stored?', isStored);
    if (!isStored) {
        await askUserToCreatePassword();
    }
}

browser.runtime.onInstalled.addListener(async details => {
    if (details.reason === 'install') {
        await initialisePassword();
    }
});

browser.runtime.onStartup.addListener(async () => {
    await initialisePassword();
});

browser.runtime.onSuspendCanceled.addListener(async () => {
    await initialisePassword();
});
