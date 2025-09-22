document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('btnregister').addEventListener('click', handleRegisterSubmit);
});

async function handleRegisterSubmit(event) {
    event.preventDefault();
    let username = document.getElementById('username').value;
    let displayName = username; // or get from another input
    // Possible values: none, direct, indirect
    let attestation_type = 'none';
    // Possible values: <empty>, platform, cross-platform
    let authenticator_attachment = '';
    // Possible values: preferred, required, discouraged
    let user_verification = 'preferred';
    // Possible values: discouraged, preferred, required
    let residentKey = 'discouraged';
    // Prepare form post data
    var data = new FormData();
    data.append('username', username);
    data.append('displayName', displayName);
    data.append('attType', attestation_type);
    data.append('authType', authenticator_attachment);
    data.append('userVerification', user_verification);
    data.append('residentKey', residentKey);
    // Send to server for registering
    let makeCredentialOptions;
    try {
        makeCredentialOptions = await fetchMakeCredentialOptions(data);
    } catch (e) {
        console.error(e);
        let msg = "Something went really wrong";
        showErrorAlert(msg);
        return;
    }
    console.log('Credential Options Object', makeCredentialOptions);
    if (makeCredentialOptions.status === 'error') {
        console.log('Error creating credential options');
        console.log(makeCredentialOptions.errorMessage);
        showErrorAlert(makeCredentialOptions.errorMessage);
        return;
    }
    // Turn the challenge back into the accepted format of padded base64
    makeCredentialOptions.challenge = coerceToArrayBuffer(makeCredentialOptions.challenge);
    // Turn ID into a UInt8Array Buffer for some reason
    makeCredentialOptions.user.id = coerceToArrayBuffer(makeCredentialOptions.user.id);
    makeCredentialOptions.excludeCredentials = makeCredentialOptions.excludeCredentials.map((c) => {
        c.id = coerceToArrayBuffer(c.id);
        return c;
    });
    if (makeCredentialOptions.authenticatorSelection.authenticatorAttachment === null) makeCredentialOptions.authenticatorSelection.authenticatorAttachment = undefined;
    console.log('Credential Options Formatted', makeCredentialOptions);
    console.log('Creating PublicKeyCredential...');
    let newCredential;
    try {
        newCredential = await navigator.credentials.create({
            publicKey: makeCredentialOptions
        });
    } catch (e) {
        var msg = 'Could not create credentials in browser. Probably because the username is already registered with your authenticator. Please change username or authenticator.';
        console.error(msg, e);
        showErrorAlert(msg, e);
        return;
    }
    console.log('PublicKeyCredential Created', newCredential);
    try {
        await registerNewCredential(newCredential, username);
    } catch (e) {
        showErrorAlert(e.message ? e.message : e);
    }
}

async function fetchMakeCredentialOptions(formData) {
    let response = await fetch('/api/fido/credential-options', {
        method: 'POST',
        body: formData,
        headers: {
            'Accept': 'application/json'
        }
    });
    let data = await response.json();
    return data;
}

// This should be used to verify the auth data with the server
async function registerNewCredential(newCredential, username) {
    // Move data into Arrays incase it is super long
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);
    const data = {
        id: newCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: newCredential.type,
        extensions: newCredential.getClientExtensionResults(),
        response: {
            attestationObject: coerceToBase64Url(attestationObject),
            clientDataJSON: coerceToBase64Url(clientDataJSON),
            transports: newCredential.response.getTransports()
        }
    };
    let response;
    try {
        response = await registerCredentialWithServer(data, username);
    } catch (e) {
        console.error('Request to server failed', e);
        showErrorAlert(e);
        return;
    }
    console.log('Credential Object', response);
    // Show error
    if (response.status === 'error') {
        console.log('Error creating credential');
        console.log(response.errorMessage);
        showErrorAlert(response.errorMessage);
        return;
    }
}

async function registerCredentialWithServer(formData, username) {
    let response = await fetch(`/api/fido/${username}/credential`, {
        method: 'PUT',
        body: JSON.stringify(formData),
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });
    let data = await response.json();
    return data;
}