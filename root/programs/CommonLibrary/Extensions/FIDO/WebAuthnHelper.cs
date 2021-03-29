//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
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
//
#endregion

//**********************************************************************************
//* クラス名        ：WebAuthnHelper
//* クラス日本語名  ：WebAuthnHelper（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/07  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Util;

using System;
using System.Text;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;

using Fido2NetLib;
using Fido2NetLib.Objects;
using Fido2NetLib.Development;
using static Fido2NetLib.Fido2;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Extensions.FIDO
{
    /// <summary>
    /// WebAuthnHelper（ライブラリ）
    /// https://github.com/abergs/fido2-net-lib/blob/master/Fido2Demo/Controller.cs
    /// </summary>
    public class WebAuthnHelper
    {
        #region mem & prop & constructor

        #region mem & prop

        /// <summary>
        /// Origin of the website: "http(s)://..."
        /// </summary>
        private string _origin = new Func<string>(() =>
        {
            string temp = Config.OAuth2AuthorizationServerEndpointsRootURI;
            Uri uri = new Uri(temp);
            temp = temp.Substring(0, temp.IndexOf(uri.Authority) + uri.Authority.Length);
            return temp;
        })();

        /// <summary>
        /// fido2-net-lib
        /// https://techinfoofmicrosofttech.osscons.jp/index.php?fido2-net-lib
        /// </summary>
        private Fido2 _lib;

        /// <summary>
        /// FIDO Alliance MetaData Service
        /// https://techinfoofmicrosofttech.osscons.jp/index.php?FIDO%E8%AA%8D%E8%A8%BC%E5%99%A8#d6659b25
        /// </summary>
        private IMetadataService _mds = null;

        #endregion

        #region constructor

        /// <summary>constructor</summary>
        public WebAuthnHelper()
        {
            // this._mds = MDSMetadata.Instance("accesskey", "cachedirPath");

            Uri uri = new Uri(this._origin);
            this._lib = new Fido2(new Fido2Configuration()
            {
                ServerDomain = uri.GetDomain(),
                ServerName = uri.GetHost(),
                Origin = this._origin,
                // Only create and use Metadataservice if we have an acesskey
                MetadataService = this._mds
            });
        }

        #endregion

        #endregion

        #region methods

        #region 登録フロー

        /// <summary>CredentialCreationOptions</summary>
        /// <param name="username">string</param>
        /// <param name="attestation">string</param>
        /// <param name="authenticatorAttachment">string</param>
        /// <param name="residentKey">string</param>
        /// <param name="userVerification">string</param>
        public CredentialCreateOptions CredentialCreationOptions(string username,
            string attestation, string authenticatorAttachment,
            bool residentKey, string userVerification)
        {
            // 1. Get user from DB by username (in our example, auto create missing users)
            // https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-user

            ApplicationUser _user = CmnUserStore.FindByName(username);

            if (_user == null)
                throw new Exception(string.Format("{0} is not found.", username));

            Fido2User user = new Fido2User
            {
                DisplayName = username,
                Name = username,
                Id = CustomEncode.StringToByte(username, CustomEncode.UTF_8)
            };

            // 2. Get user existing keys by username
            // https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
            List<PublicKeyCredentialDescriptor> existingPubCredDescriptor = DataProvider.GetCredentialsByUser(username);

            #region 3. Create options

            // https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria
            AuthenticatorSelection authenticatorSelection = new AuthenticatorSelection
            {
                RequireResidentKey = residentKey,
                UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
            };

            // https://www.w3.org/TR/webauthn/#enumdef-authenticatorattachment
            if (!string.IsNullOrEmpty(authenticatorAttachment))
                authenticatorSelection.AuthenticatorAttachment = authenticatorAttachment.ToEnum<AuthenticatorAttachment>();

            // https://www.w3.org/TR/webauthn/#dictdef-authenticationextensionsclientinputs
            // https://www.w3.org/TR/webauthn/#sctn-defined-extensions
            AuthenticationExtensionsClientInputs exts = new AuthenticationExtensionsClientInputs()
            {
                // https://www.w3.org/TR/webauthn/#sctn-supported-extensions-extension
                Extensions = true,
                // https://www.w3.org/TR/webauthn/#sctn-uvi-extension
                UserVerificationIndex = true,
                // https://www.w3.org/TR/webauthn/#sctn-location-extension
                Location = true,
                // https://www.w3.org/TR/webauthn/#sctn-uvm-extension
                UserVerificationMethod = true,
                // https://www.w3.org/TR/webauthn/#sctn-authenticator-biometric-criteria-extension
                BiometricAuthenticatorPerformanceBounds = new AuthenticatorBiometricPerfBounds
                {
                    FAR = float.MaxValue,
                    FRR = float.MaxValue
                }
            };

            // https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
            CredentialCreateOptions options = _lib.RequestNewCredential(
                // https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-user
                user,
                // https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
                existingPubCredDescriptor,
                // https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria
                authenticatorSelection,
                // https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference
                attestation.ToEnum<AttestationConveyancePreference>(),
                // https://www.w3.org/TR/webauthn/#dictdef-authenticationextensionsclientinputs
                exts);

            #endregion

            // 4. return options
            return options;
        }

        /// <summary>AuthenticatorAttestation</summary>
        /// <param name="attestationResponse">AuthenticatorAttestationRawResponse</param>
        /// <param name="options">CredentialCreateOptions</param>
        /// <returns>CredentialMakeResultを非同期的に返す</returns>
        public async Task<CredentialMakeResult> AuthenticatorAttestation(
            // https://www.w3.org/TR/webauthn/#authenticatorattestationresponse
            AuthenticatorAttestationRawResponse attestationResponse,
            // https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialcreationoptions
            CredentialCreateOptions options)
        {
            // 1. Verify and make the credentials
            CredentialMakeResult result =
                await _lib.MakeNewCredentialAsync(
                    attestationResponse, options,
                    // Storage を false になるように設計していないので、true固定。
                    async (IsCredentialIdUniqueToUserParams args) => { return true; });

            // 2. Store the credentials in db
            DataProvider.Create(
                new StoredCredential
                {
                    // https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
                    UserId = result.Result.User.Id,
                    Descriptor = new PublicKeyCredentialDescriptor(result.Result.CredentialId),
                    PublicKey = result.Result.PublicKey,
                    UserHandle = result.Result.User.Id,
                    SignatureCounter = result.Result.Counter,
                    CredType = result.Result.CredType,
                    RegDate = DateTime.Now,
                    AaGuid = result.Result.Aaguid
                });

            // 3. return result
            return result;
        }

        #endregion

        #region 認証フロー

        /// <summary>CredentialGetOptions</summary>
        /// <param name="username">string</param>
        /// <returns>AssertionOptions</returns>
        public AssertionOptions CredentialGetOptions(string username)
        {
            // 1. Get user from DB
            // https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-user
            ApplicationUser _user = CmnUserStore.FindByName(username);

            if (_user == null)
                throw new Exception(string.Format("{0} is not founded.", username));

            Fido2User user = new Fido2User
            {
                DisplayName = username,
                Name = username,
                Id = CustomEncode.StringToByte(username, CustomEncode.UTF_8)
            };

            // 2. Get registered credentials from database
            // https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
            List<PublicKeyCredentialDescriptor> existingPubCredDescriptor = DataProvider.GetCredentialsByUser(username);

            // https://www.w3.org/TR/webauthn/#dictdef-authenticationextensionsclientinputs
            // https://www.w3.org/TR/webauthn/#sctn-defined-extensions
            AuthenticationExtensionsClientInputs exts = new AuthenticationExtensionsClientInputs()
            {
                // https://www.w3.org/TR/webauthn/#sctn-appid-extension
                AppID = _origin,
                // https://www.w3.org/TR/webauthn/#sctn-simple-txauth-extension
                SimpleTransactionAuthorization = "FIDO",
                // https://www.w3.org/TR/webauthn/#sctn-generic-txauth-extension
                GenericTransactionAuthorization = new TxAuthGenericArg
                {
                    ContentType = "text/plain",
                    Content = new byte[] { 0x46, 0x49, 0x44, 0x4F }
                },
                // https://www.w3.org/TR/webauthn/#sctn-supported-extensions-extension
                // Extensions = true,
                // https://www.w3.org/TR/webauthn/#sctn-uvi-extension
                UserVerificationIndex = true,
                // https://www.w3.org/TR/webauthn/#sctn-location-extension
                Location = true,
                // https://www.w3.org/TR/webauthn/#sctn-uvm-extension
                UserVerificationMethod = true
            };

            // 3. Create options
            // https://www.w3.org/TR/webauthn/#assertion-options
            AssertionOptions options = _lib.GetAssertionOptions(
                // https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor
                existingPubCredDescriptor,
                // https://www.w3.org/TR/webauthn/#enumdef-userverificationrequirement
                UserVerificationRequirement.Discouraged,
                // https://www.w3.org/TR/webauthn/#sctn-defined-extensions
                exts
            );

            // 4. Return options to client
            return options;
        }

        /// <summary>AuthenticatorAssertion</summary>
        /// <param name="clientResponse">AuthenticatorAssertionRawResponse</param>
        /// <param name="options">AssertionOptions</param>
        /// <returns>AssertionVerificationResultを非同期的に返す</returns>
        public async Task<AssertionVerificationResult> AuthenticatorAssertion(
            AuthenticatorAssertionRawResponse clientResponse,
            AssertionOptions options)
        {
            StoredCredential storedCred = null;

            // 1. Get registered credential from database
            storedCred = DataProvider.GetCredentialById(clientResponse.Id);

            // 2. Get credential counter from database
            uint storedCounter = storedCred.SignatureCounter;

            // 3. Make the assertion
            AssertionVerificationResult result = await _lib.MakeAssertionAsync(
                clientResponse, options, storedCred.PublicKey, storedCounter,
                async (IsUserHandleOwnerOfCredentialIdParams args) =>
                {
                    // Create callback to check if userhandle owns the credentialId
                    storedCred = DataProvider.GetCredentialById(args.CredentialId);
                    return (storedCred.UserHandle == args.UserHandle);
                });

            // 4. Store the updated counter
            storedCred.SignatureCounter = result.Counter;
            DataProvider.Update(storedCred);

            // 5. return result
            return result;
        }

        #endregion

        /// <summary>FormatException</summary>
        /// <param name="e">Exception</param>
        /// <returns>string</returns>
        public static string FormatException(Exception e)
        {
            return string.Format(
                "{0}{1}",
                e.Message,
                e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
        }

        #endregion
    }
}