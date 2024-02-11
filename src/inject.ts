import { credentialsCreate, credentialsGet } from './credentials';
import { isConditionalMediationAvailable, isUserVerifyingPlatformAuthenticatorAvailable } from './webauthn';

function replaceNativeFunctions() {
    Object.defineProperty(navigator.credentials, 'create', {
        value: credentialsCreate
    });

    Object.defineProperty(navigator.credentials, 'get', {
        value: credentialsGet
    });

    Object.defineProperty(window.PublicKeyCredential, 'isConditionalMediationAvailable', { value: isConditionalMediationAvailable });

    Object.defineProperty(window.PublicKeyCredential, 'isUserVerifyingPlatformAuthenticatorAvailable', {
        value: isUserVerifyingPlatformAuthenticatorAvailable
    });
}

if (globalThis.browser) {
    const passkeys = document.createElement('script');
    passkeys.src = browser.runtime.getURL('build/bundle.js');
    document.documentElement.appendChild(passkeys);
} else {
    replaceNativeFunctions();
}
