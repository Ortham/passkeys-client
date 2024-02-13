import { createMessageListener, showDialog } from "./common.js";

async function askUserForDisclosureConsent(credential) {
    const messageElement = document.getElementById('message');

    messageElement.textContent = `${rpEntity.id} (${rpEntity.name}) wants to create a passkey for the user ${userEntity.name} (${userEntity.displayName}). Do you want to accept?`;

    return showDialog(dialog => dialog.returnValue === 'default');
}

const messageListener = createMessageListener((invoke, parameters) => {
    if (invoke === 'askUserForDisclosureConsent') {
        return askUserForDisclosureConsent(parameters.credential);
    }

    return undefined;
});

browser.runtime.onMessage.addListener(messageListener);
