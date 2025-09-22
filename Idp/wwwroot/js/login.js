document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('btnloginPasskey').addEventListener('click', handleSignInSubmit);
});

async function handleSignInSubmit(event) {
    event.preventDefault();
    let username = document.getElementById('username').value;
    // Prepare form post data
    var formData = new FormData();
    formData.append('username', username);
    // Send to server for assertion options
    let makeAssertionOptions;
    try {
        var res = await fetch(`/api/fido/assertion-options`, {
            method: 'POST',
            body: formData,
            headers: {
                'Accept': 'application/json'
            }
        });
        makeAssertionOptions = await res.json();
    } catch (e) {
        showErrorAlert('Request to server failed', e);
        return;
    }
    console.log('Assertion Options Object', makeAssertionOptions);
    // Show options error to user
    if (makeAssertionOptions.status === 'error') {
        console.log('Error creating assertion options');
        console.log(makeAssertionOptions.errorMessage);
        showErrorAlert(makeAssertionOptions.errorMessage);
        return;
    }
    makeAssertionOptions.challenge = coerceToArrayBuffer(makeAssertionOptions.challenge);
    makeAssertionOptions.allowCredentials.forEach(function (listItem) {
        listItem.id = coerceToArrayBuffer(listItem.id);
    });
    console.log('Assertion options', makeAssertionOptions);
    // Ask browser for credentials (browser will ask connected authenticators)
    let credential;
    try {
        credential = await navigator.credentials.get({ publicKey: makeAssertionOptions });
    } catch (err) {
        showErrorAlert(err.message ? err.message : err);
        return;
    }
    try {
        await verifyAssertionWithServer(credential);
    } catch (e) {
        console.error('Error verifying assertion', e);
        showErrorAlert('Could not verify assertion', e);
    }
}

/**
 * Sends the credential to the the FIDO2 server for assertion
 * @param {any} assertedCredential
 */
async function verifyAssertionWithServer(assertedCredential) {
    // Move data into Arrays incase it is super long
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    const data = {
        id: assertedCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: assertedCredential.type,
        extensions: assertedCredential.getClientExtensionResults(),
        response: {
            authenticatorData: coerceToBase64Url(authData),
            clientDataJSON: coerceToBase64Url(clientDataJSON),
            signature: coerceToBase64Url(sig)
        }
    };
    let response;
    try {
        let res = await fetch(`/api/fido/assertion`, {
            method: 'POST',
            body: JSON.stringify(data),
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });
        console.log('Response from server', res);
        response = await res.json();
    } catch (e) {
        showErrorAlert('Request to server failed', e);
        throw e;
    }
    console.log('Assertion Object', response);
    // If response is a URL, redirect
    if (typeof response === 'string' && response.startsWith('https')) {
        window.location.href = response;
        return;
    }
    // If error
    if (response.status === 'error') {
        console.log('Error doing assertion');
        console.log(response.errorMessage);
        showErrorAlert(response.errorMessage);
        return;
    }
}