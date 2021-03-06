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
//* ファイル名        ：ffWebauthn.js
//* ファイル日本語名  ：webauthn処理（Form Post用
//*
//* 作成日時        ：−
//* 作成者          ：−
//* 更新履歴        ：−
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/0?  西野 大介         新規作成
//**********************************************************************************

//**********************************************************************************
// インターフェイス
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
// 初期化
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
// 冒頭で実行
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
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
// FIDOサポートの検出
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
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
// FIDOUserVerifyingPlatformサポートの検出
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
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
// 引数    −
// 戻り値  −
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
// 引数    msg
// 戻り値  −
// ---------------------------------------------------------------
function showErrorAlert(msg) {
    $("#error-alert-msg").text(msg);
    $("#error-alert").show();
}
// ---------------------------------------------------------------
// hideErrorAlert
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
// ---------------------------------------------------------------
function hideErrorAlert() {
    $("#error-alert").hide();
}

// ---------------------------------------------------------------
// showWarningAlert
// ---------------------------------------------------------------
// 引数    msg
// 戻り値  −
// ---------------------------------------------------------------
function showWarningAlert(msg) {
    $("#warning-alert-msg").text(msg);
    $("#warning-alert").show();
}

// ---------------------------------------------------------------
// hideWarningAlert
// ---------------------------------------------------------------
// 引数    msg
// 戻り値  −
// ---------------------------------------------------------------
function hideWarningAlert() {
    $("#warning-alert").fadeOut(200);
}

// ---------------------------------------------------------------
// webauthn.makeCredentialの前半
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
// ---------------------------------------------------------------
function makeCredential1() {

    // ログ
    Fx_DebugOutput("enter makeCredential method", null);

    // 初期処理
    setInput();
    hideErrorAlert();
    hideWarningAlert();
    
    // POST JSONデータ生成
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

    // ログ
    Fx_DebugOutput("makeCredential - data:", data);

    // データのPOST
    $("#fido2Data").val(JSON.stringify(data));
    $("form").submit();
}

// ---------------------------------------------------------------
// webauthn.makeCredentialの後半
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
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

    // 引数
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
            // 戻り値
            Fx_DebugOutput("registerNewCredential - authenticatorAttestationResponse:", authenticatorAttestationResponse);
            // サーバーに登録
            registerNewCredential(authenticatorAttestationResponse);

        }).catch(function (err) {
            // 戻り値
            Fx_DebugOutput("registerNewCredential - err:", err);
            Swal.closeModal();
            showErrorAlert(err.message ? err.message : err);

        });
    }
}

// ---------------------------------------------------------------
// navigator.credentials.createの結果を登録する。
// ---------------------------------------------------------------
// 引数    authenticatorAttestationResponse
// 戻り値  −
// ---------------------------------------------------------------
function registerNewCredential(authenticatorAttestationResponse) {

    // ログ
    Fx_DebugOutput("enter registerNewCredential method", null);

    // 入力
    let attestationObject = Fx_CoerceToBase64Url(authenticatorAttestationResponse.response.attestationObject);
    let clientDataJSON = Fx_CoerceToBase64Url(authenticatorAttestationResponse.response.clientDataJSON);
    let rawId = Fx_CoerceToBase64Url(authenticatorAttestationResponse.rawId);

    // POST JSONデータ生成
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

    // ログ
    Fx_DebugOutput("registerNewCredential - data:", data);

    // データのPOST
    $("#fido2Data").val(JSON.stringify(data));
    $("form").submit();
}

// ---------------------------------------------------------------
// navigator.credentials.createの結果を登録結果
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
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
// navigator.credentials.getを実行する。
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
// ---------------------------------------------------------------
function getAssertion1() {

    // ログ
    Fx_DebugOutput("enter getAssertion method", null);

    // 初期処理
    setInput();
    hideErrorAlert();
    hideWarningAlert();
    
    // POST JSONデータ生成
    var data = {
        username: input.user.name,
        userVerification: input.user_verification
    };

    // ログ
    Fx_DebugOutput("getAssertion - data:", data);

    // データのPOST
    $("#Fido2Data").val(JSON.stringify(data));
    $("#submitButtonName").val("webauthn_signin");
    $("#LoginForm").submit();
}

// ---------------------------------------------------------------
// navigator.credentials.getを実行する。
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
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

        // サーバーで検証
        verifyAssertion(authenticatorAttestationResponse);
    }).catch(function (err) {
        console.log(err);
        showErrorAlert(err.message ? err.message : err);
        Swal.closeModal();
    });
}

// ---------------------------------------------------------------
// navigator.credentials.getの結果を取得する。
// ---------------------------------------------------------------
// 引数    authenticatorAttestationResponse
// 戻り値  −
// ---------------------------------------------------------------
function verifyAssertion(authenticatorAttestationResponse) {

    // ログ
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

    // ログ
    Fx_DebugOutput("verifyAssertion - data:", data);

    // データのPOST
    $("#Fido2Data").val(JSON.stringify(data));
    $("#submitButtonName").val("webauthn_signin");
    $("#LoginForm").submit();
}

// ---------------------------------------------------------------
// navigator.credentials.getの結果を検証する。
// ---------------------------------------------------------------
// 引数    −
// 戻り値  −
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