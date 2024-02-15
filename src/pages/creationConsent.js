import { createMessageListener, setUpUserVerification, showDialog } from "./common.js";

async function askUserForCreationConsent(rpEntity, userEntity, requireUserVerification) {
    const messageElement = document.getElementById('message');

    const message = `${rpEntity.id} (${rpEntity.name}) wants to create a passkey for the user ${userEntity.name} (${userEntity.displayName}).`;

    messageElement.textContent = message;

    await setUpUserVerification(requireUserVerification);

    return showDialog(dialog => {
        if (dialog.returnValue === 'default') {
            return { userConsented: true, userVerified: requireUserVerification };
        } else {
            return { userConsented: false, userVerified: false };
        }
    });
}

const messageListener = createMessageListener((invoke, parameters) => {
    if (invoke === 'askUserForCreationConsent') {
        return askUserForCreationConsent(parameters.rpEntity, parameters.userEntity, parameters.requireUserVerification);
    }

    return undefined;
});

browser.runtime.onMessage.addListener(messageListener);
