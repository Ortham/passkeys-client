# Passkeys Client

This is a toy implementation of a WebAuthn client and authenticator that supports passkeys which I wrote to check my understanding of how they work. **It is not safe for production use.** All messaging is unencrypted, the built-in authenticator stores credentials unencrypted, and it's probably trivial for malicious scripts to spoof any of the involved message sources.

The client is implemented as a web extension (tested in Firefox v122) that replaces the following native methods:

- `navigator.credentials.create()`
- `navigator.credentials.get()`
- `PublicKeyCredential.isConditionalMediationAvailable()`
- `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`

The implementation targets WebAuthn Level 2. Although some Level 3 functionality has been added for compatibility with third-party Relying Parties, some other Level 3 functionality is not supported.

The extension is composed of:

- A content script that injects a `<script>` element into each HTTPS and localhost page that is loaded by the browser.
- A replacer script that is injected into `localhost` and HTTPS pages, and which replaces the methods listed above and all the client logic that those methods invoke.
- A background script that provides the authenticator implementation.
- Popup pages that provide the authenticator UI for creating a password, asking for consent to create a credential, and selecting a credential.

Communication between the replacer and background scripts (i.e. between the client and the authenticator) is done by proxying messages through the content script. Intended message destinations are explicitly given in the message, and requests and responses are correlated using randomly-generated message IDs. The same approach is taken for communicating between the background script and popup pages.

Limitations:

- While the EdDSA, ES256, ES384, ES512, PS256 and RS256 credential algorithms are supported, EdDSA is not recognised by Firefox v122 or Edge v121 and so cannot be used in those web browsers.
- Transports are ignored in inputs and provided as empty arrays in outputs
- The client treats indirect attestation as if it were direct attestation
- Enterprise attestation is not supported
- No client or authenticator extensions are supported
- There's no way to cancel an operation from the client's UI (because the client has no UI)
- There's no way to use the client with any authenticator other than the built-in authenticator
- Conditional mediation is not supported (WebAuthn Level 3)
- Cross-origin `create()` and `get()` usage is not supported (WebAuthn Level 3)
- There's no way to negotiate attestation format with an authenticator (WebAuthn Level 3)
- `attestationObject` in assertion responses is always null (WebAuthn Level 3)
