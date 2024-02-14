import { PublicKeyCredentialSource } from "../types";
import { fromBase64Url, toBase64Url } from "../util";

type StoredCredential = {
    type: 'public-key';
    id: string;
    privateKey: JsonWebKey;
    rpId: string;
    userHandle: string | null;
    otherUI: {
        username: string;
        signatureCounter: number;
    };
}

const CREDENTIALS_KEY = 'credentials';
const ENCRYPTION_KEY_KEY = 'credentialIdEncryptionKey';

function getRpIdKey(rpId: string): string {
    return `${CREDENTIALS_KEY}_rpId_${rpId}`;
}

function getCredentialKey(credentialId: ArrayBuffer): string {
    return `${CREDENTIALS_KEY}_credentialId_${toBase64Url(credentialId)}`;
}

function getCredentialOtherUIKey(credentialId: ArrayBuffer): string {
    return `${CREDENTIALS_KEY}_otherUI_${toBase64Url(credentialId)}`;
}

function fromStored(credential: StoredCredential): PublicKeyCredentialSource {
    return {
        ...credential,
        id: fromBase64Url(credential.id),
        userHandle: credential.userHandle === null ? null : fromBase64Url(credential.userHandle),
    };
}

function toStored(credential: PublicKeyCredentialSource): StoredCredential {
    return {
        ...credential,
        id: toBase64Url(credential.id),
        userHandle: credential.userHandle === null ? null : toBase64Url(credential.userHandle),
    }
}

async function getCredentials(credentialKeys: string[]): Promise<PublicKeyCredentialSource[]> {
    const promises = credentialKeys.map(async credentialKey => {
        const results = await browser.storage.local.get({ [credentialKey]: null });
        return results[credentialKey];
    });

    const results: (StoredCredential | null)[] = await Promise.all(promises);
    const credentials = results.filter(c => c !== null) as StoredCredential[];

    return credentials.map(fromStored);
}

async function appendCredentialKey(targetKey: string, credentialKey: string): Promise<void> {
    const results = await browser.storage.local.get({ [targetKey]: [] });

    results[targetKey].push(credentialKey);

    await browser.storage.local.set(results);
}

export async function getAllStoredCredentials(): Promise<PublicKeyCredentialSource[]> {
    const results = await browser.storage.local.get({ [CREDENTIALS_KEY]: [] });

    return getCredentials(results[CREDENTIALS_KEY]);
}

export async function getStoredCredentials(rpId: string): Promise<PublicKeyCredentialSource[]> {
    const key = getRpIdKey(rpId);
    const results = await browser.storage.local.get({ [key]: [] });

    return getCredentials(results[key]);
}

export async function storeCredential(credential: PublicKeyCredentialSource): Promise<void> {
    const credentialKey = getCredentialKey(credential.id);

    await Promise.all([
        browser.storage.local.set({ [credentialKey]: toStored(credential) }),
        appendCredentialKey(CREDENTIALS_KEY, credentialKey),
        appendCredentialKey(getRpIdKey(credential.rpId), credentialKey)
    ]);
}

export async function incrementSignatureCounter(credential: PublicKeyCredentialSource): Promise<void> {
    const credentialKey = getCredentialKey(credential.id);
    const results = await browser.storage.local.get({ [credentialKey]: null });

    if (results[credentialKey] === null) {
        // The credential could be a client-side credential, so look for its otherUI data.
        const otherUI = await getCredentialOtherUI(credential.id);

        otherUI.signatureCounter += 1;

        await storeCredentialOtherUI(credential.id, otherUI);
    } else {
        results[credentialKey].otherUI.signatureCounter += 1;

        await browser.storage.local.set(results);
    }

    // Now also increment the counter in the credential object that was passed in, to match the stored value.
    credential.otherUI.signatureCounter += 1;
}

async function generateEncryptionKey(): Promise<JsonWebKey> {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

    return crypto.subtle.exportKey('jwk', key);
}

export async function getEncryptionKey(): Promise<JsonWebKey> {
    const results = await browser.storage.local.get({ [ENCRYPTION_KEY_KEY]: null });

    if (results[ENCRYPTION_KEY_KEY] === null) {
        // If there isn't an encryption key stored, generate and store one.
        const key = await generateEncryptionKey();

        await browser.storage.local.set({ [ENCRYPTION_KEY_KEY]: key });

        return key;
    }

    return results[ENCRYPTION_KEY_KEY];
}

// Only used for client-side credentials.
export async function storeCredentialOtherUI(credentialId: ArrayBuffer, otherUI: PublicKeyCredentialSource['otherUI']): Promise<void> {
    const key = getCredentialOtherUIKey(credentialId);

    return browser.storage.local.set({ [key]: otherUI });
}

// Only used for client-side credentials.
export async function getCredentialOtherUI(credentialId: ArrayBuffer): Promise<PublicKeyCredentialSource['otherUI']> {
    const key = getCredentialOtherUIKey(credentialId);

    const results = await browser.storage.local.get({ [key]: null });

    if (results[key] === null) {
        throw new Error('Could not find stored data for key ' + key);
    }

    return results[key];
}
