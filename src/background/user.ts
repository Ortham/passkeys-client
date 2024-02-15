import { MESSAGE_TARGET_POPUP_SCRIPT, getRandomBytes, toBase64Url } from "../util";
import { PublicKeyCredentialSource } from "../types";

type WindowOptions = {
    path: string;
    height?: number;
    width?: number;
};

async function createPopup(windowOptions: WindowOptions): Promise<number> {
    const createData = {
        allowScriptsToClose: true,
        focused: true,
        height: windowOptions.height,
        type: 'popup' as any,
        url: browser.runtime.getURL(windowOptions.path),
        width: windowOptions.width
    };

    let window: browser.windows.Window | undefined;

    // Creating a popup involves creating a window with a tab, but the create promise resolves before the tab has finished loading, so await on the tab's status being updated.
    const tabReady: Promise<number> = new Promise((resolve, _reject) => {
        browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            // Filter out other windows and tabs, in case there's more than one open for the same URL.
            if (window !== undefined
                && (window.id !== tab.windowId
                    || window.tabs?.length !== 1
                    || window.tabs?.[0]?.id !== tabId)) {
                return;
            }

            if (changeInfo.status === 'complete') {
                resolve(tabId);
            }
        }, { urls: [createData.url], properties: ['status'] })
    });

    window = await browser.windows.create(createData);

    return tabReady;
}

async function showPopup<T>(windowOptions: WindowOptions, invoke: string, parameters: Record<string, unknown>): Promise<T> {
    const tabId = await createPopup(windowOptions);

    const response = await browser.tabs.sendMessage(
        tabId,
        {
            messageId: toBase64Url(getRandomBytes(16)),
            target: MESSAGE_TARGET_POPUP_SCRIPT,
            invoke,
            parameters
        });

    console.log('Received response in background script', response);

    return response;
}

export async function askUserToCreatePassword(): Promise<void> {
    const pageOptions = {
        path: 'src/pages/createPassword.html',
        height: 300,
        width: 400
    };

    await showPopup(pageOptions, 'askUserToCreatePassword', {});
}

export async function askUserForCreationConsent(
    rpEntity: Required<PublicKeyCredentialRpEntity>,
    userEntity: PublicKeyCredentialUserEntity,
    requireUserVerification: boolean
): Promise<{ userConsented: boolean; userVerified: boolean; }> {
    const pageOptions = {
        path: 'src/pages/creationConsent.html',
        height: 400,
        width: 600
    };

    return showPopup(pageOptions, 'askUserForCreationConsent', {
        rpEntity,
        userEntity,
        requireUserVerification
    });
}

export async function askUserForSelection(
    credentialOptions: PublicKeyCredentialSource[],
    rpId: string,
    requireUserVerification: boolean
): Promise<{ selectedCredential: PublicKeyCredentialSource | undefined; userVerified: boolean; }> {
    const pageOptions = {
        path: 'src/pages/credentialSelection.html',
        height: 400,
        width: 600
    };

    return showPopup(pageOptions, 'askUserForSelection', {
        credentialOptions,
        rpId,
        requireUserVerification
    });
}
