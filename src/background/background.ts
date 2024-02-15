import { MESSAGE_TARGET_BACKGROUND_SCRIPT } from "../util";
import { authenticatorGetAssertion, authenticatorMakeCredential, lookupCredentialsById } from "./authenticator";
import { askUserToCreatePassword } from "./user";

// Although as a background script this state may be lost, it shouldn't be lost while the script is running, and it only matters then because if the script isn't running then there isn't anything to cancel.
let ABORT_CONTROLLER: AbortController | undefined;

function cleanup() {
    ABORT_CONTROLLER = undefined;
}

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
        ABORT_CONTROLLER ??= new AbortController();
        const signal = ABORT_CONTROLLER.signal;

        promise = authenticatorMakeCredential(message.parameters.hash,
            message.parameters.rpEntity,
            message.parameters.userEntity,
            message.parameters.requireResidentKey,
            message.parameters.requireUserVerification,
            message.parameters.credTypesAndPubKeyAlgs,
            message.parameters.enterpriseAttestationPossible,
            message.parameters.extensions,
            signal,
            message.parameters.excludeCredentialDescriptorList);
    } else if (message.invoke === 'authenticatorGetAssertion') {
        ABORT_CONTROLLER ??= new AbortController();
        const signal = ABORT_CONTROLLER.signal;

        promise = authenticatorGetAssertion(message.parameters.rpId,
            message.parameters.hash,
            message.parameters.requireUserVerification,
            message.parameters.extensions,
            signal,
            message.parameters.allowCredentialDescriptorList);
    } else if (message.invoke === 'authenticatorCancel') {
        // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-op-cancel
        if (ABORT_CONTROLLER !== undefined) {
            ABORT_CONTROLLER.abort();
        }
        promise = Promise.resolve();
    }

    if (promise !== undefined) {
        promise.then(sendResponse, sendResponse).finally(cleanup);
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
