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

replaceNativeFunctions();
