# Passkeys Client

This is a toy implementation of a WebAuthn client that supports passkeys which I wrote to check my understanding of how they work. **It is not safe for production use.** All messaging is unencrypted, the built-in authenticator stores credentials unencrypted, and it's probably trivial for malicious scripts to spoof any of the involved message sources.

The client is implemented as a web extension (tested in Firefox v122) that replaces the following native methods:

- `navigator.credentials.create()`
- `navigator.credentials.get()`
- `PublicKeyCredential.isConditionalMediationAvailable()`
- `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`

The implementation targets WebAuthn Level 2, so some methods and functionality added in the Level 3 draft are not supported.

Then the replacement `navigator.credentials` methods are called, they call replacement  implementations of the internal `PublicKeyCredential` methods that are used by WebAuthn. Those implementations communicate with an authenticator, which the extension also provides.

The extension is composed of:

- A content script that injects a `<script>` element into each HTTPS and localhost page that is loaded by the browser.
- A replacer script that is injected into the pages, and which replaces the methods listed above. The replacement includes the internal `PublicKeyCredential` methods, as they return
- A background script that provides the authenticator implementation.

The replacer script includes all client logic, because some of the internal `PublicKeyCredential` methods that are the lowest level of that logic return functions, and so cannot be called across `Window` objects (i.e. the page can't trigger them by posting a message to the content script, because the return value can't be serialised).

The authenticator logic lives in a background script: the replacer script communicates with the authenticator using `window.postMessage()` to send a message to the content script, and this is then forwarded to the background script using `browser.runtime.sendMessage`. The background script invokes the appropriate authenticator function and responds with its return value. The content script waits for this responds and then uses `window.postMessage()` to send it back to the replacer script. The messages between the replacer and content scripts are correlated using randomly-generated message IDs, and their target is determined based on the structure of their content.
