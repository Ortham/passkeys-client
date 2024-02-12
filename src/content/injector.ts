const passkeys = document.createElement('script');
passkeys.src = browser.runtime.getURL('build/bundle/replacer.js');
document.documentElement.appendChild(passkeys);

window.addEventListener('message', async event => {
    if (event.origin !== window.origin
        || event.source !== window
        || event.data.result !== undefined) {
        return;
    }

    console.log('Received message in content script', event);

    const result = await browser.runtime.sendMessage(event.data);

    console.log('Received response in content script', result);

    window.postMessage({
        messageId: event.data.messageId,
        result
    }, window.origin);
});
