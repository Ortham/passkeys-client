export const MESSAGE_TARGET_POPUP_SCRIPT = 'popup-script';
const PASSWORD_KEY = 'user_password';

async function getStoredPassword() {
    const results = await browser.storage.local.get({ [PASSWORD_KEY]: null });
    return results[PASSWORD_KEY];
}

export async function storePassword(password) {
    return browser.storage.local.set({ [PASSWORD_KEY]: password });
}

export async function setUpUserVerification(requireUserVerification) {
    const passwordField = document.getElementById('passwordField');
    const passwordInput = document.getElementById('password');

    passwordField.hidden = !requireUserVerification;
    passwordInput.required = requireUserVerification;

    if (!requireUserVerification) {
        return;
    }

    const storedPassword = await getStoredPassword();

    passwordInput.addEventListener('change', () => {
        if (passwordInput.value !== storedPassword) {
            passwordInput.setCustomValidity('Password is not correct!');
        } else {
            passwordInput.setCustomValidity('');
        }
    });
}

export function showDialog(getMessageResponse) {
    const dialog = document.querySelector('dialog');

    return new Promise((resolve, reject) => {
        dialog.addEventListener('close', async () => {
            try {
                // getMessageResponse may return a Promise, but Promises don't nest so that's fine.
                resolve(getMessageResponse(dialog));

                await browser.windows.remove(browser.windows.WINDOW_ID_CURRENT);
            } catch (err) {
                reject(err);
            }
        });

        dialog.show();
    });
}

export function createMessageListener(invoker) {
    return (message, sender, sendResponse) => {
        if (message.target !== MESSAGE_TARGET_POPUP_SCRIPT) {
            return;
        }

        console.log('Received message in popup script', message, 'from', sender);

        const promise = invoker(message.invoke, message.parameters);

        if (promise !== undefined) {
            promise.then(sendResponse, sendResponse);
            return true;
        }

        return false;
    }
}
