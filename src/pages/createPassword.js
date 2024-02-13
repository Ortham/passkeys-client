import { createMessageListener, showDialog, storePassword } from "./common.js";

function askUserToCreatePassword() {
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirmPassword');

    function validatePasswordsMatch() {
        if (passwordInput.value === confirmPasswordInput.value) {
            confirmPasswordInput.setCustomValidity('');
        } else {
            confirmPasswordInput.setCustomValidity('Passwords do not match!');
        }
    }

    passwordInput.addEventListener('change', validatePasswordsMatch);
    confirmPasswordInput.addEventListener('change', validatePasswordsMatch);

    return showDialog(async dialog => {
        if (dialog.returnValue === 'default') {
            await storePassword(passwordInput.value);
        } else {
            throw new Error('User cancelled create password dialog');
        }
    });
}

const messageListener = createMessageListener((invoke, _parameters) => {
    if (invoke === 'askUserToCreatePassword') {
        return askUserToCreatePassword();
    }

    return undefined;
});

browser.runtime.onMessage.addListener(messageListener);
