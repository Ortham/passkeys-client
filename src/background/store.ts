import { fromBase64Url, toBase64Url } from "../util";

export type PublicKeyCredentialSource = {
    type: 'public-key';
    id: ArrayBuffer;
    privateKey: JsonWebKey;
    rpId: string;
    userHandle: ArrayBuffer | null;
    otherUI: {
        signatureCounter: number;
    };
};

type StoredCredential = {
    type: 'public-key';
    id: string;
    privateKey: JsonWebKey;
    rpId: string;
    userHandle: string | null;
    otherUI: {
        signatureCounter: number;
    };
}

const CREDENTIALS_KEY = 'credentials';

function getRpIdKey(rpId: string): string {
    return `${CREDENTIALS_KEY}_rpId_${rpId}`;
}

function getCredentialKey(credentialId: ArrayBuffer): string {
    return `${CREDENTIALS_KEY}_credentialId_${toBase64Url(credentialId)}`;
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

export async function incrementSignatureCounter(credentialId: ArrayBuffer): Promise<void> {
    const credentialKey = getCredentialKey(credentialId);
    const results = await browser.storage.local.get({ [credentialKey]: null });

    if (results[credentialKey] === null) {
        throw new Error('Could not find stored credential for key ' + credentialKey);
    }

    results[credentialKey].otherUI.signatureCounter += 1;

    await browser.storage.local.set(results);
}
