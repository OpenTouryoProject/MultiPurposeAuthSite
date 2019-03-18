// https://github.com/abergs/fido2-net-lib/blob/master/Fido2Demo/wwwroot/js/webauthn.js

//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
//**********************************************************************************

// Apache License
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License. 
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//**********************************************************************************
//* �t�@�C����        �FffWebauthn.js
//* �t�@�C�����{�ꖼ  �Fwebauthn�����iForm Post�p
//*
//* �쐬����        �F�|
//* �쐬��          �F�|
//* �X�V����        �F�|
//*
//*  ����        �X�V��            ���e
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/0?  ���� ���         �V�K�쐬
//**********************************************************************************

//**********************************************************************************
// �C���^�[�t�F�C�X
//**********************************************************************************
// Input items
// - button
//   - #register-button
//   - #webauthn_signin
// - hidden
//   - #userName
//   - #inputUsername
// - select and checkbox
//   - #select-attestation
//   - #select-authenticator
//   - #select-userVerification
//   - #checkbox-residentCredentials
// Output items
// - alert
//   - #error-alert
//   - #error-alert-msg
//   - #warning-alert
//   - #warning-alert-msg

//**********************************************************************************
// ������
//**********************************************************************************
if (window.location.protocol !== "https:") {
    showErrorAlert("Please use HTTPS");}

// input object
var input = {
    attestationType: null,
    authenticatorAttachment: null,
    userVerification: null,
    requireResidentKey: null,

    user: {
        name: "",
        displayName: ""
    }
};

// ---------------------------------------------------------------
// �`���Ŏ��s
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function setInput() {
    
    let username = $("#userName").val();

    if (username) {
        localStorage["userId"] = username;
        input.attestationType = $('#select-attestation').find(':selected').val();
        input.authenticatorAttachment = $('#select-authenticator').find(':selected').val();
        input.userVerification = $('#select-userVerification').find(':selected').val();
        input.requireResidentKey = $("#checkbox-residentCredentials").is(':checked');
    }
    else {
        username = localStorage["userId"];
        input.userVerification = $('#select-userVerification').find(':selected').val();
    }

    input.user.name = username.toLowerCase().replace(/\s/g, '');
    input.user.displayName = username.toLowerCase();
}

// ---------------------------------------------------------------
// FIDO�T�|�[�g�̌��o
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function detectFIDOSupport() {
    if (window.PublicKeyCredential === undefined || typeof window.PublicKeyCredential !== "function") {
        $('#register-button').attr("disabled", true);
        $('#webauthn_signin').attr("disabled", true);
        showErrorAlert("WebAuthn is not currently supported on this browser.");
        return;
    }
}

// ---------------------------------------------------------------
// FIDOUserVerifyingPlatform�T�|�[�g�̌��o
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function detectFIDOUserVerifyingPlatformSupport() {
    if (window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
        markPlatformAuthenticatorUnavailable();
    } else if (typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(function (available) {
            if (!available) {
                markPlatformAuthenticatorUnavailable();
            }
        }).catch(function (e) {
            markPlatformAuthenticatorUnavailable();
        });
    }
}

// ---------------------------------------------------------------
// markPlatformAuthenticatorUnavailable
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function markPlatformAuthenticatorUnavailable() {
    var authenticator_attachment = $('#select-authenticator').find(':selected').val();
    var user_verification = $('#select-userVerification').find(':selected').val();

    if (authenticator_attachment === "platform" && user_verification === "required") {
        showWarningAlert("User verifying platform authenticators are not currently supported on this browser.");
    }
}

//**********************************************************************************
// Alert
//**********************************************************************************
// ---------------------------------------------------------------
// showErrorAlert
// ---------------------------------------------------------------
// ����    msg
// �߂�l  �|
// ---------------------------------------------------------------
function showErrorAlert(msg) {
    $("#error-alert-msg").text(msg);
    $("#error-alert").show();
}
// ---------------------------------------------------------------
// hideErrorAlert
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function hideErrorAlert() {
    $("#error-alert").hide();
}

// ---------------------------------------------------------------
// showWarningAlert
// ---------------------------------------------------------------
// ����    msg
// �߂�l  �|
// ---------------------------------------------------------------
function showWarningAlert(msg) {
    $("#warning-alert-msg").text(msg);
    $("#warning-alert").show();
}

// ---------------------------------------------------------------
// hideWarningAlert
// ---------------------------------------------------------------
// ����    msg
// �߂�l  �|
// ---------------------------------------------------------------
function hideWarningAlert() {
    $("#warning-alert").fadeOut(200);
}

// ---------------------------------------------------------------
// webauthn.makeCredential�̑O��
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function makeCredential1() {

    // ���O
    Fx_DebugOutput("enter makeCredential method", null);

    // ��������
    setInput();
    hideErrorAlert();
    hideWarningAlert();
    
    // POST JSON�f�[�^����
    // https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#example-credential-creation-options
    const data = {
        username: input.user.name,
        displayName: input.user.name,
        authenticatorSelection: {
            residentKey: input.requireResidentKey,
            authenticatorAttachment: input.authenticatorAttachment,
            userVerification: input.userVerification
        },
        attestation: input.attestationType
    };

    // ���O
    Fx_DebugOutput("makeCredential - data:", data);

    // �f�[�^��POST
    $("#fido2Data").val(JSON.stringify(data));
    $("form").submit();
}

// ---------------------------------------------------------------
// webauthn.makeCredential�̌㔼
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function makeCredential2() {

    let publicKeyCredentialCreationOptions = JSON.parse($("#fido2Data").val());

    // Normal
    Fx_DebugOutput("registerNewCredential - publicKeyCredentialCreationOptions 1:", publicKeyCredentialCreationOptions);

    if (publicKeyCredentialCreationOptions.status !== "ok") {
        showErrorAlert(publicKeyCredentialCreationOptions.errorMessage);
        return;
    }

    // JSON to CredentialCreationOptions

    // To ArrayBuffer
    publicKeyCredentialCreationOptions.challenge = Fx_CoerceToArrayBuffer(publicKeyCredentialCreationOptions.challenge);
    publicKeyCredentialCreationOptions.user.id = Fx_CoerceToArrayBuffer(publicKeyCredentialCreationOptions.user.id);
    publicKeyCredentialCreationOptions.excludeCredentials = publicKeyCredentialCreationOptions.excludeCredentials.map((c) => {
        c.id = Fx_CoerceToArrayBuffer(c.id);
        return c;
    });
    // null -> undefined
    if (publicKeyCredentialCreationOptions.authenticatorSelection.authenticatorAttachment === null)
        publicKeyCredentialCreationOptions.authenticatorSelection.authenticatorAttachment = undefined;

    // ����
    Fx_DebugOutput("registerNewCredential - publicKeyCredentialCreationOptions 2:", publicKeyCredentialCreationOptions);

    // SweetAlert
    let confirmed = true;
    Swal.fire({
        title: 'Registering...',
        text: 'Tap your security key to finish registration.',
        imageUrl: "/images/securitykey.min.svg",
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false

    }).then(function (result) {
        if (!result.value) {
            confirmed = false;
            Fx_DebugOutput('Registration cancelled', null);
        }

    }).catch(function (error) {
        confirmed = false;
        Fx_DebugOutput("SweetAlert Error:", error);
    });

    // Credential Management API (navigator.credentials.create)
    if (confirmed) {
        navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions

        }).then(function (authenticatorAttestationResponse) {
            // �߂�l
            Fx_DebugOutput("registerNewCredential - authenticatorAttestationResponse:", authenticatorAttestationResponse);
            // �T�[�o�[�ɓo�^
            registerNewCredential(authenticatorAttestationResponse);

        }).catch(function (err) {
            // �߂�l
            Fx_DebugOutput("registerNewCredential - err:", err);
            Swal.closeModal();
            showErrorAlert(err.message ? err.message : err);

        });
    }
}

// ---------------------------------------------------------------
// navigator.credentials.create�̌��ʂ�o�^����B
// ---------------------------------------------------------------
// ����    authenticatorAttestationResponse
// �߂�l  �|
// ---------------------------------------------------------------
function registerNewCredential(authenticatorAttestationResponse) {

    // ���O
    Fx_DebugOutput("enter registerNewCredential method", null);

    // ����
    let attestationObject = Fx_CoerceToBase64Url(authenticatorAttestationResponse.response.attestationObject);
    let clientDataJSON = Fx_CoerceToBase64Url(authenticatorAttestationResponse.response.clientDataJSON);
    let rawId = Fx_CoerceToBase64Url(authenticatorAttestationResponse.rawId);

    // POST JSON�f�[�^����
    const data = {
        id: authenticatorAttestationResponse.id,
        rawId: rawId,
        type: authenticatorAttestationResponse.type,
        extensions: authenticatorAttestationResponse.getClientExtensionResults(),
        response: {
            AttestationObject: attestationObject,
            clientDataJson: clientDataJSON
        }
    };

    // ���O
    Fx_DebugOutput("registerNewCredential - data:", data);

    // �f�[�^��POST
    $("#fido2Data").val(JSON.stringify(data));
    $("form").submit();
}

// ---------------------------------------------------------------
// navigator.credentials.create�̌��ʂ�o�^����
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function registeredNewCredential() {

    let responseJson = JSON.parse($("#fido2Data").val());

    // Normal
    Fx_DebugOutput("registerNewCredential - responseJson:", responseJson);

    if (responseJson.status !== "ok") {
        Swal.closeModal();
        showErrorAlert(responseJson.errorMessage);
        return;
    }

    // SweetAlert
    Swal.fire({
        title: 'Registration Successful!',
        text: 'You\'ve registered successfully.',
        type: 'success',
        timer: 2000
    }).then(function (result) {
        $("form").submit();
    });
}

// ---------------------------------------------------------------
// navigator.credentials.get�����s����B
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function getAssertion1() {

    // ���O
    Fx_DebugOutput("enter getAssertion method", null);

    // ��������
    setInput();
    hideErrorAlert();
    hideWarningAlert();
    
    // POST JSON�f�[�^����
    var data = {
        username: input.user.name,
        userVerification: input.user_verification
    };

    // ���O
    Fx_DebugOutput("getAssertion - data:", data);

    // �f�[�^��POST
    $("#Fido2Data").val(JSON.stringify(data));
    $("#submitButtonName").val("webauthn_signin");
    $("#LoginForm").submit();
}

// ---------------------------------------------------------------
// navigator.credentials.get�����s����B
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function getAssertion2() {

    let publicKeyCredentialRequestOptions = JSON.parse($("#Fido2Data").val());

    // Normal
    Fx_DebugOutput("getAssertion - publicKeyCredentialRequestOptions 1:", publicKeyCredentialRequestOptions);

    if (publicKeyCredentialRequestOptions.status !== "ok") {
        showErrorAlert(publicKeyCredentialRequestOptions.errorMessage);
        return;
    }

    // JSON to PublicKeyCredentialRequestOptions
    const challenge = publicKeyCredentialRequestOptions.challenge.replace(/-/g, "+").replace(/_/g, "/");
    publicKeyCredentialRequestOptions.challenge = Fx_CoerceToArrayBuffer(challenge);

    publicKeyCredentialRequestOptions.allowCredentials.forEach(function (listItem) {
        var fixedId = listItem.id.replace(/\_/g, "/").replace(/\-/g, "+");
        listItem.id = Fx_CoerceToArrayBuffer(fixedId);
    });

    Fx_DebugOutput("getAssertion - publicKeyCredentialRequestOptions 2:", publicKeyCredentialRequestOptions);

    // SweetAlert
    let confirmed = true;
    Swal.fire({
        title: 'Logging In...',
        text: 'Tap your security key to login.',
        imageUrl: "/images/securitykey.min.svg",
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false

    }).then(function (result) {
        if (!result.value) {
            confirmed = false;
            Fx_DebugOutput('Login cancelled', null);
        }

    }).catch(function (error) {
        confirmed = false;
        Fx_DebugOutput("SweetAlert Error:", error);
    });

    // Credential Management API (navigator.credentials.get)
    navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions

    }).then(function (authenticatorAttestationResponse) {
        console.log("getAssertion - authenticatorAttestationResponse:");
        console.log(authenticatorAttestationResponse);
        console.log(JSON.stringify(authenticatorAttestationResponse));

        // �T�[�o�[�Ō���
        verifyAssertion(authenticatorAttestationResponse);
    }).catch(function (err) {
        console.log(err);
        showErrorAlert(err.message ? err.message : err);
        Swal.closeModal();
    });
}

// ---------------------------------------------------------------
// navigator.credentials.get�̌��ʂ��擾����B
// ---------------------------------------------------------------
// ����    authenticatorAttestationResponse
// �߂�l  �|
// ---------------------------------------------------------------
function verifyAssertion(authenticatorAttestationResponse) {

    // ���O
    Fx_DebugOutput("enter verifyAssertion method", null);

    // Move data into Arrays incase it is super long
    let authData = Fx_CoerceToBase64Url(authenticatorAttestationResponse.response.authenticatorData);
    let clientDataJSON = Fx_CoerceToBase64Url(authenticatorAttestationResponse.response.clientDataJSON);
    let rawId = Fx_CoerceToBase64Url(authenticatorAttestationResponse.rawId);
    let sig = Fx_CoerceToBase64Url(authenticatorAttestationResponse.response.signature);

    const data = {
        id: authenticatorAttestationResponse.id,
        rawId: rawId,
        type: authenticatorAttestationResponse.type,
        extensions: authenticatorAttestationResponse.getClientExtensionResults(),
        response: {
            authenticatorData: authData,
            clientDataJson: clientDataJSON,
            signature: sig
        }
    };

    // ���O
    Fx_DebugOutput("verifyAssertion - data:", data);

    // �f�[�^��POST
    $("#Fido2Data").val(JSON.stringify(data));
    $("#submitButtonName").val("webauthn_signin");
    $("#LoginForm").submit();
}

// ---------------------------------------------------------------
// navigator.credentials.get�̌��ʂ����؂���B
// ---------------------------------------------------------------
// ����    �|
// �߂�l  �|
// ---------------------------------------------------------------
function verifiedAssertion() {

    let responseJson = JSON.parse($("#Fido2Data").val());

    // Normal
    Fx_DebugOutput("verifyAssertion - responseJson:", responseJson);

    if (responseJson.status !== "ok") {
        Swal.closeModal();
        showErrorAlert(responseJson.errorMessage);
        return;
    }
}