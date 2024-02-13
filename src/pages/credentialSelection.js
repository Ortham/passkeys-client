import { createMessageListener, setUpUserVerification, showDialog } from "./common.js";

function toBase64Url(array) {
    return btoa(String.fromCharCode(...new Uint8Array(array)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function listCredentials(selectElement, credentials) {
    while (selectElement.firstElementChild !== null) {
        selectElement.removeChild(selectElement.firstElementChild);
    }

    for (const credential of credentials) {
        const option = document.createElement('option');
        option.value = toBase64Url(credential.id);
        option.textContent = credential.otherUI.username;

        selectElement.appendChild(option);
    }
}

async function askUserForSelection(credentialOptions, rpId, requireUserVerification) {
    const selectMessageElement = document.getElementById('selectMessage');
    const credentialSelect = document.getElementById('credentialSelect');

    selectMessageElement.textContent = `Please select a passkey to use to sign into ${rpId}.`;

    listCredentials(credentialSelect, credentialOptions);

    await setUpUserVerification(requireUserVerification);

    return showDialog(dialog => {
        if (dialog.returnValue === 'default') {
            const selectedCredential = credentialOptions.find(c => toBase64Url(c.id) === credentialSelect.value);

            return { selectedCredential, userVerified: requireUserVerification };
        } else {
            return { selectedCredential: undefined, userVerified: false };
        }
    });
}

const messageListener = createMessageListener((invoke, parameters) => {
    if (invoke === 'askUserForSelection') {
        return askUserForSelection(parameters.credentialOptions, parameters.rpId, parameters.requireUserVerification);
    }

    return undefined;
});


browser.runtime.onMessage.addListener(messageListener);
