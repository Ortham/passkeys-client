import { MESSAGE_TARGET_BACKGROUND_SCRIPT, MESSAGE_TARGET_CONTENT_SCRIPT, MESSAGE_TARGET_PAGE_SCRIPT } from "../util";

const passkeys = document.createElement('script');
passkeys.src = browser.runtime.getURL('build/bundle/replacer.js');
document.documentElement.appendChild(passkeys);

window.addEventListener('message', async event => {
    if (event.origin !== window.origin
        || event.source !== window
        || event.data.target !== MESSAGE_TARGET_CONTENT_SCRIPT) {
        return;
    }

    console.log('Received message in content script', event);

    const result = await browser.runtime.sendMessage({
        ...event.data,
        target: MESSAGE_TARGET_BACKGROUND_SCRIPT
    });

    console.log('Received response in content script', result);

    window.postMessage({
        messageId: event.data.messageId,
        target: MESSAGE_TARGET_PAGE_SCRIPT,
        result
    }, window.origin);
});
